"""
is5.py - Parser/Extraktor fuer InstallShield-5.x-Cabinet-Archive (.hdr/.cab)

Reine Python-Implementierung, kein externes Binary noetig.
Struktur-Layout und Algorithmen 1:1 aus dem unshield-Quellcode
(https://github.com/twogood/unshield, MIT-Lizenz) uebernommen -
nur der major_version-5/0-Zweig (IS5.0 / 5.1 / 5.5) ist implementiert.
IS6+ (anderes File-Descriptor-Layout, 0x57 Bytes statt variabel) und
IS3-.Z-Archive (anderer Kompressionsalgorithmus, PKWare "explode")
werden NICHT unterstuetzt.

Multi-Volume-Unterstuetzung (data1.cab, data2.cab, ...): Fuer jede
Datei wird - wie im Original - anhand der Volume-Header (first/last
file index) das richtige Startvolume gesucht (ISCabHeader.resolve_volume()).
Dateien, deren Rohdaten selbst ueber eine oder mehrere Volume-Grenzen
hinweg gesplittet sind, werden von _VolumeReader transparent
zusammengelesen (Portierung von unshield_reader_open_volume() /
unshield_reader_read() aus file.c).

Status: gegen den unshield-Sourcecode nachgebaut, aber NICHT gegen ein
echtes IS5.x-Archiv getestet (mir lag keine Testdatei vor). Bei Fehlern
bitte Fehlermeldung + Datei-Ausschnitt (erste 128 Bytes als Hex) melden.
"""

import os
import shutil
import struct
import zlib

CAB_SIGNATURE = 0x28635349  # "ISc(" little-endian
COMMON_HEADER_SIZE = 20
VOLUME_HEADER_SIZE_V5 = 40
MAX_FILE_GROUP_COUNT = 71
MAX_COMPONENT_COUNT = 71

FILE_SPLIT = 0x1
FILE_OBFUSCATED = 0x2
FILE_COMPRESSED = 0x4
FILE_INVALID = 0x8


class ISCabError(Exception):
    pass


class VolumeNotFoundError(ISCabError):
    """Ein benoetigtes Volume (z.B. data2.cab) wurde weder im
    Ursprungsordner noch in einem via register_volume_folder()
    registrierten Ordner gefunden - typischerweise, weil die
    Volumes auf verschiedenen Datentraegern (z.B. CD1/CD2) liegen.
    volume_index/filename lassen den Aufrufer gezielt nach dem
    richtigen Ordner fragen und es erneut versuchen."""

    def __init__(self, volume_index, filename, searched_folders):
        self.volume_index = volume_index
        self.filename = filename
        self.searched_folders = searched_folders
        self.context = ""  # Diagnosetext, vom Aufrufer gesetzt (siehe _get_volume_header_retrying)
        super().__init__(
            "Volume-Datei '%s' nicht gefunden (durchsucht: %s)."
            % (filename, ", ".join(searched_folders) or "-")
        )


def _read_cstr(data, offset):
    if offset == 0:
        return ""
    if offset < 0 or offset >= len(data):
        raise ISCabError(
            "Ungueltiger String-Offset %d (Dateigroesse %d) - vermutlich "
            "Datenmuell in einem als ungueltig markierten Eintrag." % (offset, len(data))
        )
    end = data.find(b"\x00", offset)
    if end == -1:
        raise ISCabError(
            "Kein Null-Terminator ab Offset %d gefunden (Dateigroesse %d) - "
            "vermutlich Datenmuell in einem als ungueltig markierten Eintrag." % (offset, len(data))
        )
    return data[offset:end].decode("latin-1")


def _ror8(x, n):
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def _deobfuscate(buf, seed):
    """Entspricht unshield_deobfuscate() in file.c."""
    out = bytearray(buf)
    for i in range(len(out)):
        b = out[i] ^ 0xD5
        b = _ror8(b, 2)
        b = (b - (seed % 0x47)) & 0xFF
        out[i] = b
        seed += 1
    return bytes(out), seed


class FileEntry:
    __slots__ = (
        "index", "name", "directory_index", "directory_name",
        "flags", "expanded_size", "compressed_size", "data_offset",
        "volume",
    )

    @property
    def compressed(self):
        return bool(self.flags & FILE_COMPRESSED)

    @property
    def obfuscated(self):
        return bool(self.flags & FILE_OBFUSCATED)

    @property
    def invalid(self):
        """Echtes FILE_INVALID-Flag: geloeschter/Platzhalter-Eintrag,
        vom Archiv selbst als ungueltig markiert (kein Inhalt mehr
        vorhanden, war es aber im Sinne der Cab-Struktur einmal)."""
        return bool(self.flags & FILE_INVALID)

    @property
    def not_embedded(self):
        """data_offset==0 UND kein FILE_INVALID-Flag: die Datei ist
        real Teil des Setups, aber gar nicht im Cab eingebettet -
        typischerweise eine ganze Dateigruppe, die im IS-Projekt auf
        'nicht komprimieren' gestellt wurde. Solche Dateien liegen
        unveraendert auf dem Datentraeger/Quellverzeichnis (gleiche
        Ordnerstruktur wie 'directory_name') und werden vom Setup per
        Dateikopie statt Cab-Extraktion installiert. Aus DIESEM Cab
        lassen sie sich nicht extrahieren - falls vorhanden, muessen
        sie direkt aus dem Quellverzeichnis kopiert werden."""
        return not self.invalid and self.data_offset == 0

    def is_external(self, header):
        """Umfassenderer Check als not_embedded: erkennt zusaetzlich eine
        zweite, real beobachtete Variante desselben 'nicht eingebettet'-
        Zustands (gesehen bei einem major_version==0-Archiv/IS5.1) - dort
        bleibt FILE_COMPRESSED gesetzt und data_offset zeigt NICHT auf 0,
        sondern exakt auf das Ende der (selbsttragenden) Cab-Datei: der
        gesamte Cab-Inhalt besteht nur aus dem Katalog, fuer echte Daten
        ist kein Platz mehr. Ohne diesen Zusatz-Check wuerde extract_file()
        hier mit einem irrefuehrenden 'Unerwartetes Dateiende' scheitern,
        statt den eigentlichen Grund zu nennen."""
        if self.not_embedded:
            return True
        if self.invalid:
            return False
        # Variante B gilt nur fuer selbsttragende .cab (Katalog + Daten in
        # einer Datei). Bei separater .hdr liegen die Daten in dataN.cab,
        # data_offset ist dann relativ dazu und kann beliebig > len(.hdr) sein.
        if header.path.lower().endswith(".hdr"):
            return False
        if self.volume == 1 and self.data_offset >= len(header.data):
            return True
        return False

    @property
    def rel_path(self):
        if self.directory_name:
            return self.directory_name.replace("\\", "/") + "/" + self.name
        return self.name


class ISCabHeader:
    """Parst eine .hdr- oder .cab-Datei (Header-/Verzeichnisteil)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        if len(self.data) < COMMON_HEADER_SIZE:
            raise ISCabError("Datei zu klein fuer einen gueltigen Header.")
        self._parse_common()
        self._parse_cab_descriptor()
        self._parse_file_table()
        self._volume_header_cache = {}
        self._volume_folder_overrides = {}  # volume_index -> Ordner (z.B. gemountetes CD2-ISO)
        self._volume_path_overrides = {}  # volume_index -> exakter Dateipfad
        self.external_source_dir = None  # Ordner fuer nicht eingebettete (not_embedded) Dateien

    def _parse_common(self):
        sig, version, volume_info, cab_off, cab_size = struct.unpack_from(
            "<5I", self.data, 0
        )
        if sig != CAB_SIGNATURE:
            if sig == 0x4643534D:  # "MSCF"
                raise ISCabError(
                    "Das ist ein Microsoft-CAB (MSCF-Signatur), kein "
                    "InstallShield-CAB. Dafuer z.B. expand.exe/7-Zip nutzen."
                )
            raise ISCabError(
                "Keine gueltige InstallShield-CAB-Signatur (erwartet 'ISc(')."
            )
        self.version = version
        self.volume_info = volume_info
        self.cab_descriptor_offset = cab_off
        self.cab_descriptor_size = cab_size

        if (version >> 24) == 1:
            self.major_version = (version >> 12) & 0xF
        elif (version >> 24) in (2, 4):
            mv = version & 0xFFFF
            self.major_version = (mv // 100) if mv else 0
        else:
            self.major_version = 0

        if self.major_version not in (0, 5):
            raise ISCabError(
                "Major-Version %r wird von diesem Tool nicht unterstuetzt "
                "(nur IS5.0/5.1/5.5 implementiert, kein IS6+)." % self.major_version
            )

    def _parse_cab_descriptor(self):
        if not self.cab_descriptor_size:
            raise ISCabError("Kein CAB-Descriptor in der Datei vorhanden.")

        base = self.cab_descriptor_offset
        p = base + 0xC
        (self.file_table_offset,) = struct.unpack_from("<I", self.data, p); p += 4
        p += 4
        (self.file_table_size,) = struct.unpack_from("<I", self.data, p); p += 4
        (self.file_table_size2,) = struct.unpack_from("<I", self.data, p); p += 4
        (self.directory_count,) = struct.unpack_from("<I", self.data, p); p += 4
        p += 8
        (self.file_count,) = struct.unpack_from("<I", self.data, p); p += 4
        (self.file_table_offset2,) = struct.unpack_from("<I", self.data, p); p += 4

        assert (p - base) == 0x30, "Cab-Descriptor-Layout unerwartet (0x%x)" % (p - base)

    def _parse_file_table(self):
        base = self.cab_descriptor_offset + self.file_table_offset
        count = self.directory_count + self.file_count
        self.file_table = list(
            struct.unpack_from("<%dI" % count, self.data, base)
        )

        self.directories = []
        for i in range(self.directory_count):
            off = base + self.file_table[i]
            self.directories.append(_read_cstr(self.data, off))

        self.files = []
        for i in range(self.file_count):
            fe = self._read_file_descriptor(i, base)
            self.files.append(fe)

    def _read_file_descriptor(self, index, base):
        off = base + self.file_table[self.directory_count + index]
        p = off
        fe = FileEntry()
        fe.index = index
        fe.volume = 1  # Single-Volume-Annahme; siehe find_volume_file()

        (name_offset,) = struct.unpack_from("<I", self.data, p); p += 4
        (fe.directory_index,) = struct.unpack_from("<H", self.data, p); p += 2
        p += 2
        (fe.flags,) = struct.unpack_from("<H", self.data, p); p += 2
        (fe.expanded_size,) = struct.unpack_from("<I", self.data, p); p += 4
        (fe.compressed_size,) = struct.unpack_from("<I", self.data, p); p += 4
        p += 0x14
        (fe.data_offset,) = struct.unpack_from("<I", self.data, p); p += 4

        if self.major_version == 5:
            p += 0x10  # MD5, wird hier nicht geprueft
            assert (p - off) == 0x3A
        else:
            assert (p - off) == 0x2A

        fe.name = self._read_entry_name(base, name_offset, fe.flags)
        if 0 <= fe.directory_index < len(self.directories):
            fe.directory_name = self.directories[fe.directory_index]
        else:
            fe.directory_name = ""

        return fe

    def _read_entry_name(self, base, name_offset, flags):
        """Liest den Dateinamen; bei als FILE_INVALID markierten
        Eintraegen koennen die uebrigen Felder (inkl. name_offset)
        einfach Datenmuell aus einem geloeschten Slot sein - dann wird
        ein Platzhaltername verwendet, statt das Laden des GESAMTEN
        Archivs an einem einzigen kaputten Eintrag scheitern zu lassen."""
        try:
            return _read_cstr(self.data, base + name_offset)
        except ISCabError:
            if flags & FILE_INVALID:
                return "<ungueltiger Eintrag>"
            raise

    def register_volume_folder(self, volume_index, folder):
        """Registriert einen zusaetzlichen Ordner, in dem nach dem
        Volume dataN.cab gesucht wird (z.B. der Mountpunkt der
        zweiten CD/ISO) - fuer den Fall, dass die Volumes nicht alle
        im selben Ordner wie die urspruenglich geladene .hdr/.cab
        liegen. Wirft die zwischengespeicherte VolumeHeader-Info fuer
        dieses Volume weg, falls schon (erfolglos) versucht."""
        self._volume_folder_overrides[volume_index] = folder
        self._volume_header_cache.pop(volume_index, None)

    def register_volume_path(self, volume_index, path):
        """Wie register_volume_folder(), aber mit exaktem Dateipfad statt
        Ordner - fuer den Fall, dass der Nutzer per Datei-Dialog direkt
        auf die (ggf. anders benannte) Volume-Datei gezeigt hat, statt
        nur einen Ordner auszuwaehlen."""
        self._volume_path_overrides[volume_index] = path
        self._volume_header_cache.pop(volume_index, None)

    def register_external_source_dir(self, folder):
        """Registriert einen Ordner, in dem nach NICHT eingebetteten
        (not_embedded) Dateien gesucht wird, falls sie nicht direkt
        neben der geladenen .hdr/.cab liegen (z.B. wenn nur ein Teil
        des Original-CD-Baums vorliegt)."""
        self.external_source_dir = folder
    def _get_volume_header(self, volume_index):
        """Liest Common-Header + V5-Volume-Header von dataN.cab (gecacht).
        Entspricht dem major_version<=5-Zweig von
        unshield_reader_open_volume() in file.c."""
        if volume_index in self._volume_header_cache:
            return self._volume_header_cache[volume_index]

        _, prefix = _find_volume_prefix(self.path)
        candidate_name = "%s%d.cab" % (prefix, volume_index)

        searched = []
        path = None

        exact_override = self._volume_path_overrides.get(volume_index)
        if exact_override:
            path = exact_override if os.path.isfile(exact_override) else None
            if path is None:
                searched.append(exact_override)

        if path is None:
            override_folder = self._volume_folder_overrides.get(volume_index)
            if override_folder:
                searched.append(override_folder)
                path = _find_case_insensitive(override_folder, candidate_name)

        if path is None:
            original_folder, _ = _find_volume_prefix(self.path)
            searched.append(original_folder)
            path = find_volume_file(self.path, volume_index, raise_on_missing=False)

        if path is None:
            raise VolumeNotFoundError(volume_index, candidate_name, searched)

        with open(path, "rb") as f:
            common = f.read(COMMON_HEADER_SIZE)
            if len(common) != COMMON_HEADER_SIZE:
                raise ISCabError("Volume %d ('%s'): Header unvollstaendig." % (volume_index, path))
            sig = struct.unpack_from("<I", common, 0)[0]
            if sig != CAB_SIGNATURE:
                raise ISCabError("Volume %d ('%s') hat keine gueltige ISc(-Signatur." % (volume_index, path))

            vh_data = f.read(VOLUME_HEADER_SIZE_V5)
            if len(vh_data) != VOLUME_HEADER_SIZE_V5:
                raise ISCabError("Volume %d ('%s'): Volume-Header unvollstaendig." % (volume_index, path))

        (data_offset, _unknown, first_file_index, last_file_index,
         first_file_offset, first_file_size_expanded, first_file_size_compressed,
         last_file_offset, last_file_size_expanded, last_file_size_compressed
         ) = struct.unpack("<10I", vh_data)

        # Nie befuellter Volume-Header (alles 0) bei einem Archiv mit >1
        # Datei: kann kein echter Header sein (Index 0 == last_file_index
        # bei Teilgroesse 0 an Offset 0) -> Volume traegt alles. Sonst
        # wuerde schon die zweite Datei nach einem Volume 2 suchen.
        unpopulated = (
            first_file_index == 0 and last_file_index == 0
            and first_file_offset == 0 and last_file_offset == 0
            and first_file_size_compressed == 0 and last_file_size_compressed == 0
            and self.file_count > 1
        )
        if unpopulated:
            last_file_index = self.file_count - 1

        if last_file_offset == 0:
            last_file_offset = 0x7FFFFFFF  # Sentinel wie im Original (INT32_MAX)

        vh = {
            "path": path,
            "first_file_index": first_file_index,
            "last_file_index": last_file_index,
            "first_file_offset": first_file_offset,
            "first_file_size_expanded": first_file_size_expanded,
            "first_file_size_compressed": first_file_size_compressed,
            "last_file_offset": last_file_offset,
            "last_file_size_expanded": last_file_size_expanded,
            "last_file_size_compressed": last_file_size_compressed,
        }
        self._volume_header_cache[volume_index] = vh
        return vh

    def resolve_volume(self, entry):
        """Findet das Volume, in dem der globale File-Index von `entry`
        tatsaechlich liegt (data1.cab, data2.cab, ...). Entspricht der
        Schleife in unshield_reader_create() in file.c: solange
        entry.index > last_file_index des aktuellen Volumes ist, wird
        das naechste Volume probiert."""
        volume = entry.volume
        tried = set()
        while True:
            if volume in tried:
                raise ISCabError(
                    "Volume-Aufloesung fuer '%s' laeuft im Kreis (Volume %d)."
                    % (entry.rel_path, volume)
                )
            tried.add(volume)
            vh = self._get_volume_header(volume)
            if entry.index > vh["last_file_index"]:
                volume += 1
                continue
            return volume, vh


def _find_volume_prefix(header_path):
    """Leitet aus z.B. 'data1.hdr' das Praefix 'data' ab (erster Punkt
    oder Ziffer im Dateinamen beendet das Praefix), analog
    unshield_create_filename_pattern()."""
    folder, base = os.path.split(header_path)
    prefix = base
    for i, ch in enumerate(base):
        if ch == "." or ch.isdigit():
            prefix = base[:i]
            break
    return folder, prefix


def _find_case_insensitive(folder, filename):
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return None
    for entry in entries:
        if entry.lower() == filename.lower():
            return os.path.join(folder, entry)
    return None


def find_volume_file(header_path, volume_index, raise_on_missing=True):
    """Sucht dataN.cab (case-insensitive) neben der geladenen Datei.
    raise_on_missing=False gibt None statt einer Exception zurueck,
    damit Aufrufer (z.B. ISCabHeader._get_volume_header) selbst
    entscheiden koennen, wie sie mit einem fehlenden Volume umgehen
    (z.B. den Nutzer nach einem anderen Ordner/Datentraeger fragen)."""
    folder, prefix = _find_volume_prefix(header_path)
    candidate = "%s%d.cab" % (prefix, volume_index)
    found = _find_case_insensitive(folder, candidate)
    if found:
        return found
    # Fallback: die urspruenglich geladene Datei selbst (z.B. wenn
    # kein separates .hdr existiert und die Daten im .cab stecken)
    if volume_index == 1:
        return header_path
    if raise_on_missing:
        raise VolumeNotFoundError(volume_index, candidate, [folder])
    return None


def _vh_context(header, entry, vh, volume, why):
    """Kurzer Diagnosetext fuer den 'Volume fehlt'-Dialog: zeigt, WARUM
    ein weiteres Volume verlangt wird (Header-Werte des aktuellen Volumes
    gegen die Werte des Datei-Eintrags)."""
    return (
        "%s | Datei-Index %d/%d, major_version=%d, compressed_size=%d, data_offset=%d | "
        "Volume %d: first_file_index=%d, last_file_index=%d, "
        "last_file_offset=%d, last_file_size_compressed=%d, first_file_size_compressed=%d"
        % (why, entry.index, header.file_count, header.major_version,
           entry.compressed_size, entry.data_offset, volume,
           vh["first_file_index"], vh["last_file_index"],
           vh["last_file_offset"], vh["last_file_size_compressed"],
           vh["first_file_size_compressed"])
    )


def _get_volume_header_retrying(header, volume_index, on_missing_volume, context=""):
    """Wie header._get_volume_header(), aber gibt bei VolumeNotFoundError
    dem Aufrufer (ueber den on_missing_volume-Callback) die Chance, einen
    Pfad zu registrieren und es erneut zu versuchen - z.B. fuer einen
    "Datei suchen"-Dialog. on_missing_volume(exc) -> bool: True = erneut
    versuchen, False/None = Fehler weiterreichen."""
    while True:
        try:
            return header._get_volume_header(volume_index)
        except VolumeNotFoundError as e:
            e.context = context
            if on_missing_volume is not None and on_missing_volume(e):
                continue
            raise


class _VolumeReader:
    """Liest eine logisch zusammenhaengende Byte-Sequenz, die ueber
    mehrere dataN.cab-Volumes verteilt sein kann. Portierung von
    unshield_reader_open_volume() + unshield_reader_read() aus file.c.

    Split-Erkennung: Ein Volume-Header traegt first_file_index/
    last_file_index (welche Datei dort beginnt/endet) sowie die
    jeweilige Teil-Groesse. Weicht diese Teil-Groesse von der
    Gesamtgroesse im File-Descriptor ab, ist die Datei an dieser
    Volume-Grenze gesplittet - der "Rest" liegt dann im Nachbarvolume
    und wird beim Ueberlauf automatisch nachgeladen (siehe read()).

    on_missing_volume: optionaler Callback fuer den Fall, dass ein
    benoetigtes Volume (Start- oder Folgevolume) nicht gefunden wird -
    z.B. weil Volume 1 und Volume 2 auf verschiedenen CDs/ISOs liegen
    und nicht gleichzeitig eingelegt sein koennen. Wird der Callback
    genau in dem Moment aufgerufen, in dem das VORHERIGE Volume schon
    vollstaendig gelesen (und die bereits entschluesselten Daten schon
    auf die Zieldatei geschrieben) sind - der Nutzer kann also in Ruhe
    die Medien wechseln, ohne dass etwas verloren geht oder neu gelesen
    werden muss.
    """

    def __init__(self, header, entry, on_missing_volume=None):
        self.header = header
        self.entry = entry
        self.file = None
        self.volume = None
        self.bytes_left_in_volume = 0
        self.seed = 0  # Obfuskierungs-Seed laeuft ueber die GESAMTE Lesefolge
        self.on_missing_volume = on_missing_volume

        volume, vh = self._resolve_start_volume()
        self._open_volume_for_read(volume, vh)

    def _resolve_start_volume(self):
        """Wie header.resolve_volume(), aber mit Retry-Unterstuetzung
        (siehe _get_volume_header_retrying)."""
        volume = self.entry.volume
        tried = set()
        prev_vh = None
        while True:
            if volume in tried:
                raise ISCabError(
                    "Volume-Aufloesung fuer '%s' laeuft im Kreis (Volume %d)."
                    % (self.entry.rel_path, volume)
                )
            tried.add(volume)
            vh = _get_volume_header_retrying(
                self.header, volume, self.on_missing_volume,
                context=_vh_context(self.header, self.entry, prev_vh, volume - 1,
                                    "Startvolume-Suche") if prev_vh else "")
            if self.entry.index > vh["last_file_index"]:
                prev_vh = vh
                volume += 1
                continue
            return volume, vh

    def _split_offsets_for_volume(self, vh):
        """Ermittelt, ob entry in DIESEM Volume nur teilweise liegt, und
        falls ja, an welcher Stelle/mit welcher Groesse.

        Split-Erkennung nur fuer major_version == 5 (exakt, nicht <= 5) -
        das Original (file.c) prueft explizit nur auf 5, nicht auf 0.
        Fuer major_version 0 wird also nie FILE_SPLIT hergeleitet."""
        entry = self.entry

        if self.header.major_version != 5:
            return entry.data_offset, entry.compressed_size, entry.expanded_size

        file_count = self.header.file_count

        is_last_here = (
            entry.index < file_count - 1
            and entry.index == vh["last_file_index"]
            and vh["last_file_size_compressed"] != entry.compressed_size
            # Teilstueck muss real sein (Groesse>0, Offset gesetzt) und die
            # Datei darf nicht komplett in dieses Volume passen - sonst ist
            # sie nicht gesplittet, sondern der Header unbrauchbar.
            and vh["last_file_size_compressed"] > 0
            and vh["last_file_offset"] != 0x7FFFFFFF
            and entry.data_offset + entry.compressed_size > os.path.getsize(vh["path"])
        )
        if is_last_here:
            return vh["last_file_offset"], vh["last_file_size_compressed"], vh["last_file_size_expanded"]

        is_first_here = (
            entry.index > 0
            and entry.index == vh["first_file_index"]
            and vh["first_file_size_compressed"] != entry.compressed_size
            and vh["first_file_size_compressed"] > 0
            and vh["first_file_offset"] > 0
        )
        if is_first_here:
            return vh["first_file_offset"], vh["first_file_size_compressed"], vh["first_file_size_expanded"]

        return entry.data_offset, entry.compressed_size, entry.expanded_size

    def _open_volume_for_read(self, volume, vh):
        self._vh = vh
        data_offset, size_compressed, size_expanded = self._split_offsets_for_volume(vh)

        f = open(vh["path"], "rb")
        f.seek(0)
        common = f.read(COMMON_HEADER_SIZE)
        if len(common) == COMMON_HEADER_SIZE:
            sig = struct.unpack_from("<I", common, 0)[0]
            if sig != CAB_SIGNATURE:
                f.close()
                raise ISCabError("Volume-Datei '%s' hat keine gueltige ISc(-Signatur." % vh["path"])

        f.seek(data_offset)

        if self.file:
            self.file.close()
        self.file = f
        self.volume = volume
        self.bytes_left_in_volume = size_compressed if self.entry.compressed else size_expanded

    def read(self, size):
        """Liest genau `size` Bytes; oeffnet bei Bedarf automatisch das
        naechste Volume (dataN+1.cab) und liest dort weiter."""
        out = bytearray()
        remaining = size

        while remaining > 0:
            to_read = min(remaining, self.bytes_left_in_volume)
            if to_read > 0:
                chunk = self.file.read(to_read)
                if len(chunk) != to_read:
                    raise ISCabError(
                        "Unerwartetes Dateiende in Volume %d ('%s') fuer '%s'."
                        % (self.volume, os.path.basename(self.file.name), self.entry.rel_path)
                    )
                out += chunk
                remaining -= to_read
                self.bytes_left_in_volume -= to_read

            if remaining == 0:
                break

            # Dieses Volume ist erschoepft (alles bereits gelesen und in
            # extract_file() schon auf die Zieldatei geschrieben), aber es
            # werden noch Bytes gebraucht -> naechstes Volume oeffnen.
            # Filehandle des ALTEN Volumes VOR der (ggf. blockierenden)
            # Nutzer-Nachfrage schliessen, damit z.B. eine CD/ISO in Ruhe
            # ausgeworfen/gewechselt werden kann.
            if self.file:
                self.file.close()
                self.file = None

            next_volume = self.volume + 1
            vh = _get_volume_header_retrying(
                self.header, next_volume, self.on_missing_volume,
                context=_vh_context(self.header, self.entry, self._vh, self.volume,
                                    "Volume %d zu Ende gelesen, Datei noch nicht komplett" % self.volume))
            self._open_volume_for_read(next_volume, vh)

        result = bytes(out)
        if self.entry.obfuscated:
            result, self.seed = _deobfuscate(result, self.seed)
        return result

    def close(self):
        if self.file:
            self.file.close()
            self.file = None


class _FramingMismatch(Exception):
    """Interne Meldung: die angenommene Chunk-Rahmung passt nicht zu den Daten."""


END_OF_CHUNK = b"\x00\x00\xff\xff"  # zlib-Sync-Flush-Marker (leerer Stored-Block)


def _inflate_new_framing(reader, entry, out):
    """Standard-Rahmung: je Chunk 2-Byte-Laenge (LE) + raw-deflate-Daten."""
    total_written = 0
    bytes_left = entry.compressed_size
    while bytes_left > 0:
        chunk_size = struct.unpack("<H", reader.read(2))[0]
        bytes_left -= 2
        if chunk_size == 0 or chunk_size > bytes_left:
            raise _FramingMismatch("chunk_size=%d bei verbleibenden %d Bytes" % (chunk_size, bytes_left))
        chunk = reader.read(chunk_size)
        bytes_left -= chunk_size
        try:
            d = zlib.decompressobj(-15)
            decompressed = d.decompress(chunk + b"\x00") + d.flush()
        except zlib.error as e:
            raise _FramingMismatch("zlib: %s" % e)
        out.write(decompressed)
        total_written += len(decompressed)
    if total_written != entry.expanded_size:
        raise _FramingMismatch("Groesse %d statt %d" % (total_written, entry.expanded_size))
    return total_written


def _inflate_old_framing(reader, entry, out):
    """Alternative Rahmung (Port von unshield_file_save_old): Chunks enden am
    Sync-Flush-Marker 00 00 FF FF. Ein Marker, dessen Folgebyte Bit 0 gesetzt hat,
    liegt MITTEN in einem Chunk (erstes Bit eines neuen Blocks ist immer 0)."""
    buf = reader.read(entry.compressed_size)
    pos = 0
    total_written = 0
    while pos < len(buf) and total_written < entry.expanded_size:
        end = buf.find(END_OF_CHUNK, pos)
        if end == -1:
            raise _FramingMismatch("kein Sync-Flush-Marker ab Byte %d" % pos)
        while end + 4 < len(buf) and (buf[end + 4] & 1):
            nxt = buf.find(END_OF_CHUNK, end + 4)
            if nxt == -1:
                raise _FramingMismatch("Chunk-Ende nicht gefunden ab Byte %d" % (end + 4))
            end = nxt
        try:
            d = zlib.decompressobj(-15)
            decompressed = d.decompress(buf[pos:end] + b"\x00") + d.flush()
        except zlib.error as e:
            raise _FramingMismatch("zlib: %s" % e)
        out.write(decompressed)
        total_written += len(decompressed)
        pos = end + 4
    if total_written != entry.expanded_size:
        raise _FramingMismatch("Groesse %d statt %d" % (total_written, entry.expanded_size))
    return total_written


def _raw_peek(header, entry):
    """Diagnose: erste 16 und letzte 8 Rohbytes der komprimierten Daten (Hex),
    damit bei unbekannter Rahmung ein Screenshot reicht."""
    try:
        _vol, vh = header.resolve_volume(entry)
        with open(vh["path"], "rb") as f:
            f.seek(entry.data_offset)
            head = f.read(16)
            f.seek(max(0, entry.data_offset + entry.compressed_size - 8))
            tail = f.read(8)
        return "Rohbytes @%d: %s ... Ende: %s" % (entry.data_offset, head.hex(" "), tail.hex(" "))
    except Exception:  # noqa: BLE001 - reine Diagnose
        return ""


def extract_file(header, entry, out_path, on_missing_volume=None):
    """Extrahiert einen FileEntry nach out_path.

    Liest ueber _VolumeReader, der Volume-Grenzen (auch bei
    gesplitteten Dateien, ueber genau eine oder mehrere Grenzen
    hinweg) transparent handhabt.

    on_missing_volume: siehe _VolumeReader - Callback fuer den Fall,
    dass ein Volume nicht gefunden wird (z.B. andere CD/ISO noetig).
    """
    if entry.invalid:
        raise ISCabError("Datei '%s' ist als ungueltig markiert." % entry.rel_path)
    if entry.is_external(header):
        raise ISCabError(
            "'%s' ist nicht im Cab eingebettet (vermutlich als 'nicht komprimieren' "
            "markiert) - die Datei liegt unveraendert im Quellverzeichnis/auf dem "
            "Datentraeger (Ordner '%s') und muss von dort direkt kopiert werden, "
            "statt aus dem Cab entpackt zu werden." % (entry.rel_path, entry.directory_name or ".")
        )

    reader = _VolumeReader(header, entry, on_missing_volume=on_missing_volume)
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

        with open(out_path, "wb") as out:
            total_written = 0

            if entry.compressed:
                try:
                    total_written = _inflate_new_framing(reader, entry, out)
                except _FramingMismatch as e_new:
                    # Zweite, reale Rahmung (unshield_file_save_old): Chunk-Grenzen
                    # ueber den Sync-Flush-Marker statt ueber ein 2-Byte-Laengenpraefix.
                    # Frischer Reader (Obfuskierungs-Seed neu), Zieldatei zuruecksetzen.
                    reader.close()
                    reader = _VolumeReader(header, entry, on_missing_volume=on_missing_volume)
                    out.seek(0)
                    out.truncate()
                    try:
                        total_written = _inflate_old_framing(reader, entry, out)
                    except _FramingMismatch as e_old:
                        raise ISCabError(
                            "'%s': weder die Laengenpraefix-Rahmung (%s) noch die "
                            "Sync-Flush-Rahmung (%s) passt. %s"
                            % (entry.rel_path, e_new, e_old, _raw_peek(header, entry))
                        )
            else:
                bytes_left = entry.expanded_size
                CHUNK = 1024 * 1024
                while bytes_left > 0:
                    to_read = min(CHUNK, bytes_left)
                    raw = reader.read(to_read)
                    out.write(raw)
                    total_written += len(raw)
                    bytes_left -= to_read
    finally:
        reader.close()

    if total_written != entry.expanded_size:
        raise ISCabError(
            "Groesse stimmt nicht: erwartet %d, geschrieben %d (Datei: %s)"
            % (entry.expanded_size, total_written, entry.rel_path)
        )


def _resolve_case_insensitive_path(base_dir, rel_path):
    """Loest rel_path (mit '/' getrennt, siehe FileEntry.rel_path)
    Segment fuer Segment case-insensitiv unterhalb von base_dir auf -
    fuer den Fall, dass Gross-/Kleinschreibung zwischen Cab-Katalog und
    tatsaechlicher Quelldatei abweicht (z.B. bei Kopien von einem
    case-sensitiven Dateisystem). Gibt den echten Pfad zurueck oder
    None, wenn irgendein Segment fehlt."""
    current = base_dir
    for part in rel_path.split("/"):
        if not part:
            continue
        found = _find_case_insensitive(current, part)
        if found is None:
            return None
        current = found
    return current


def copy_external_file(header, entry, out_path, on_missing_source=None):
    """Kopiert eine NICHT im Cab eingebettete Datei (entry.not_embedded)
    direkt aus dem Quellverzeichnis - Standardmaessig der Ordner, in
    dem die geladene .hdr/.cab liegt, oder header.external_source_dir,
    falls per register_external_source_dir() gesetzt.

    on_missing_source: optionaler Callback fuer den Fall, dass die
    Quelldatei dort nicht gefunden wird - Signatur
    on_missing_source(entry, durchsuchter_ordner) -> bool (True = nach
    register_external_source_dir() erneut versuchen).
    """
    if entry.invalid:
        raise ISCabError("Datei '%s' ist als ungueltig markiert." % entry.rel_path)
    if not entry.is_external(header):
        raise ISCabError(
            "'%s' ist im Cab eingebettet - dafuer extract_file() verwenden, "
            "nicht copy_external_file()." % entry.rel_path
        )

    tried = set()
    while True:
        base_dir = header.external_source_dir or os.path.dirname(header.path)
        src = _resolve_case_insensitive_path(base_dir, entry.rel_path)
        if src is not None and os.path.isfile(src):
            break

        tried.add(base_dir)
        if on_missing_source is not None and on_missing_source(entry, base_dir):
            continue
        raise ISCabError(
            "Quelldatei fuer '%s' nicht gefunden (durchsucht: %s)."
            % (entry.rel_path, ", ".join(tried))
        )

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    shutil.copy2(src, out_path)

    actual_size = os.path.getsize(out_path)
    if actual_size != entry.expanded_size:
        raise ISCabError(
            "'%s' kopiert, aber Groesse stimmt nicht: erwartet %d, tatsaechlich %d "
            "(evtl. falsche/veraltete Quelldatei?)."
            % (entry.rel_path, entry.expanded_size, actual_size)
        )
