"""
is3.py - Parser/Extraktor fuer InstallShield-3-Archive (.Z-Dateien,
i3comp.exe-Format).

Header-/Directory-/File-Entry-Layout aus zwei unabhaengigen Quellen
kreuzvalidiert: isdecomp.h (https://github.com/putara/isdecomp, WTFPL)
und idecomp.py (https://github.com/lephilousophe/idecomp, GPLv3) -
Letztere hat zusaetzlich das Split-Archiv-Layout (dataN -> <basis>.2,
<basis>.3, ...) und die Bit-Bedeutungen im Flags-Feld (STORED/INVALID/
HAS_VERSION/SPLIT) aufgeloest, die isdecomp.h nur als "unknown" fuehrte.
Die eigentliche Dekompression laeuft ueber blast.py (Portierung von
Mark Adlers blast.c).

Unterstuetzt: normale Dateien, nicht komprimierte (stored) Dateien,
ungueltige (geloeschte) Eintraege, und ueber mehrere Archivteile
gesplittete Dateien (inkl. Nachfragen bei fehlendem Folgeteil, siehe
extract_file(on_missing_part=...)).

Status: Der Dekompressions-Kern (blast.py) ist gegen Mark Adlers
eigenen dokumentierten Referenz-Testvektor verifiziert (und stimmt mit
idecomp.py's unabhaengiger Implementierung ueberein). Header-Offsets
sind gegen zwei unabhaengige Quellen abgeglichen und an einem echten
i3comp-Archiv (LithTech-Tools, 33 Dateien) erfolgreich getestet. Die
Split-Archiv-Logik ist NUR synthetisch getestet (Selbsttests), noch
nicht gegen ein echtes mehrteiliges IS3-Archiv.
"""

import os
import struct

from blast import blast_decompress, BlastError

SIGNATURE = bytes([0x13, 0x5D, 0x65, 0x8C, 0x3A, 0x01, 0x02, 0x00])
HEADER_SIZE = 0xFF  # Header ist 255 Bytes inkl. Padding

CBMIN_DIRENTRY = 6
CBMIN_FILEENTRY = 0x1E

FLAG_SPLIT = 0x1


class IS3Error(Exception):
    pass


class IS3PartNotFoundError(IS3Error):
    """Ein benoetigter Archivteil (z.B. SETUP.2) wurde nicht gefunden -
    typischerweise, weil die Teile auf verschiedenen Datentraegern
    (z.B. Diskette 1/2) liegen. part_id/filename lassen den Aufrufer
    gezielt nach dem richtigen Ordner/der Datei fragen."""

    def __init__(self, part_id, filename):
        self.part_id = part_id
        self.filename = filename
        super().__init__("Archivteil %d ('%s') nicht gefunden." % (part_id, filename))


def _find_case_insensitive(folder, filename):
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return None
    for entry in entries:
        if entry.lower() == filename.lower():
            return os.path.join(folder, entry)
    return None


def _u8(data, off):
    return data[off]


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


class DirEntry:
    __slots__ = ("index", "name", "num_files")


class FileEntry:
    __slots__ = (
        "index", "name", "directory_index", "directory_name",
        "size", "comp_size", "comp_offset", "attributes", "raw_flags",
        "partial", "seq_first", "seq_last",
    )

    # Bit-Bedeutungen im 16-Bit-Flags-Feld (Offset 0x19 im File-Entry),
    # aus idecomp.py (https://github.com/lephilousophe/idecomp) - dort
    # unabhaengig von isdecomp.h reverse-engineert:
    #   0x100 = Datei ueber mehrere Archivteile gesplittet (== "partial")
    #   0x040 = hat Versionsinfo (nicht immer gesetzt)
    #   0x020 = ungueltig (von icomp beim Entfernen von Dateien genutzt)
    #   0x010 = gespeichert, NICHT komprimiert
    FLAG_SPLIT = 0x100
    FLAG_HAS_VERSION = 0x40
    FLAG_INVALID = 0x20
    FLAG_STORED = 0x10

    @property
    def invalid(self):
        return bool(self.raw_flags & self.FLAG_INVALID)

    @property
    def stored(self):
        """True = nicht komprimiert, Rohdaten direkt im Archiv."""
        return bool(self.raw_flags & self.FLAG_STORED)

    @property
    def compressed(self):
        return not self.stored

    @property
    def rel_path(self):
        if self.directory_name:
            return self.directory_name.replace("\\", "/") + "/" + self.name
        return self.name


class IS3Header:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

        if len(self.data) < HEADER_SIZE:
            raise IS3Error("Datei zu klein fuer einen gueltigen IS3-Header.")
        if self.data[:8] != SIGNATURE:
            raise IS3Error(
                "Keine gueltige InstallShield-3-Signatur "
                "(erwartet 13 5D 65 8C 3A 01 02 00)."
            )

        self.num_files = _u16(self.data, 0x0C)
        self.datetime = _u32(self.data, 0x0E)
        self.archive_size = _u32(self.data, 0x12)
        self.total_size = _u32(self.data, 0x16)
        self.dir_offset = _u32(self.data, 0x29)
        self.num_dirs = _u16(self.data, 0x31)
        self.file_offset = _u32(self.data, 0x33)

        flags = _u16(self.data, 0x0A)
        self.split = bool(flags & FLAG_SPLIT)
        if self.split:
            self.num_split = _u8(self.data, 0x1E)
            self.cur_seq = _u8(self.data, 0x1F)
            # Grenzmarken fuer Split-Dateien in DIESEM Teil (siehe
            # idecomp.py, https://github.com/lephilousophe/idecomp):
            # end_integral_data/start_integral_data trennen den
            # "rueberlaufenden" Datenbereich vom Bereich, wo bereits
            # wieder vollstaendige (nicht gesplittete) Dateien beginnen.
            self.end_integral_data = _u32(self.data, 0x21)
            self.start_integral_data = _u32(self.data, 0x25)
        else:
            self.num_split = 0
            self.cur_seq = 1
            self.end_integral_data = 0
            self.start_integral_data = 0

        if self.dir_offset >= self.archive_size or self.file_offset >= self.archive_size:
            raise IS3Error("Header-Offsets liegen ausserhalb der Archivgroesse - beschaedigt?")

        self._parse_directories()
        self._parse_files()

        self._part_cache = {self.cur_seq: self}
        self._part_folder_overrides = {}
        self._part_path_overrides = {}

    def register_part_folder(self, part_id, folder):
        """Registriert einen zusaetzlichen Ordner, in dem nach Archivteil
        `part_id` gesucht wird (z.B. wenn Teile auf verschiedenen
        Datentraegern liegen)."""
        self._part_folder_overrides[part_id] = folder
        self._part_cache.pop(part_id, None)

    def register_part_path(self, part_id, path):
        """Wie register_part_folder(), aber mit exaktem Dateipfad."""
        self._part_path_overrides[part_id] = path
        self._part_cache.pop(part_id, None)

    def _part_candidate_name(self, part_id):
        """Namensschema fuer Archivteile: <Basisname ohne Endung>.<Nummer>
        (z.B. SETUP.Z -> SETUP.2, SETUP.3, ...), siehe idecomp.py."""
        _folder, base = os.path.split(self.path)
        stem, _ext = os.path.splitext(base)
        return "%s.%d" % (stem, part_id)

    def get_part(self, part_id):
        """Liefert den IS3Header fuer Archivteil `part_id` (gecacht,
        gegebenenfalls per register_part_folder()/register_part_path()
        an einem anderen Ort gesucht). Bei nicht gesplitteten Archiven
        immer self, unabhaengig von part_id."""
        if not self.split:
            return self

        if part_id in self._part_cache:
            return self._part_cache[part_id]

        candidate_name = self._part_candidate_name(part_id)
        path = None

        exact = self._part_path_overrides.get(part_id)
        if exact and os.path.isfile(exact):
            path = exact

        if path is None:
            override_folder = self._part_folder_overrides.get(part_id)
            if override_folder:
                path = _find_case_insensitive(override_folder, candidate_name)

        if path is None:
            original_folder, _ = os.path.split(self.path)
            path = _find_case_insensitive(original_folder, candidate_name)

        if path is None:
            raise IS3PartNotFoundError(part_id, candidate_name)

        part_header = IS3Header(path)
        self._part_cache[part_id] = part_header
        return part_header

    def _read_string(self, offset, length):
        return self.data[offset: offset + length].decode("latin-1", errors="replace")

    def _parse_directories(self):
        self.directories = []
        offset = self.dir_offset
        for i in range(self.num_dirs):
            if offset + CBMIN_DIRENTRY > len(self.data):
                raise IS3Error("Verzeichnis-Eintrag %d: Datei zu kurz." % i)
            num_files = _u16(self.data, offset + 0)
            hdr_size = _u16(self.data, offset + 2)
            name_len = _u8(self.data, offset + 4)
            if hdr_size < CBMIN_DIRENTRY:
                raise IS3Error("Verzeichnis-Eintrag %d: hdr_size zu klein." % i)

            d = DirEntry()
            d.index = i
            d.num_files = num_files
            d.name = self._read_string(offset + CBMIN_DIRENTRY, name_len)
            self.directories.append(d)

            offset += hdr_size

    def _parse_files(self):
        self.files = []
        offset = self.file_offset
        for i in range(self.num_files):
            if offset + CBMIN_FILEENTRY > len(self.data):
                raise IS3Error("Datei-Eintrag %d: Datei zu kurz." % i)

            seq_last = _u8(self.data, offset + 0x00)
            directory = _u16(self.data, offset + 0x01)
            size = _u32(self.data, offset + 0x03)
            comp_size = _u32(self.data, offset + 0x07)
            comp_offset = _u32(self.data, offset + 0x0B)
            attributes = _u8(self.data, offset + 0x13)
            hdr_size = _u16(self.data, offset + 0x17)
            # Volles 16-Bit-Flags-Feld (nicht nur das eine Split-Bit,
            # das isdecomp.h separat als "partial"-Byte dokumentiert -
            # das ist bitgleich mit FLAG_SPLIT, aber im selben Feld
            # stecken auch STORED/INVALID/HAS_VERSION, siehe FileEntry).
            raw_flags = _u16(self.data, offset + 0x19)
            partial = bool(raw_flags & FileEntry.FLAG_SPLIT)
            seq_first = _u8(self.data, offset + 0x1C)
            name_len = _u8(self.data, offset + 0x1D)

            if hdr_size < CBMIN_FILEENTRY:
                raise IS3Error("Datei-Eintrag %d: hdr_size zu klein." % i)

            fe = FileEntry()
            fe.index = i
            fe.raw_flags = raw_flags
            fe.directory_index = directory
            fe.size = size
            fe.comp_size = comp_size
            fe.comp_offset = comp_offset
            fe.attributes = attributes
            fe.partial = bool(partial)
            fe.seq_first = seq_first
            fe.seq_last = seq_last
            fe.name = self._read_string(offset + CBMIN_FILEENTRY, name_len)

            if 0 <= directory < len(self.directories):
                fe.directory_name = self.directories[directory].name
            else:
                fe.directory_name = ""

            self.files.append(fe)
            offset += hdr_size


def _get_part_retrying(header, part_id, on_missing_part):
    """Wie header.get_part(), aber gibt bei IS3PartNotFoundError dem
    Aufrufer (ueber den on_missing_part-Callback) die Chance, einen
    Pfad/Ordner zu registrieren und es erneut zu versuchen."""
    while True:
        try:
            return header.get_part(part_id)
        except IS3PartNotFoundError as e:
            if on_missing_part is not None and on_missing_part(e):
                continue
            raise


def _gather_split_data(header, entry, on_missing_part):
    """Sammelt die rohen (komprimierten oder gespeicherten) Bytes einer
    ueber mehrere Archivteile gesplitteten Datei und gibt sie als EINEN
    zusammenhaengenden Bytestring zurueck. Layout pro Teil nach
    idecomp.py (https://github.com/lephilousophe/idecomp):
      - im ersten beteiligten Teil: ab entry.comp_offset
      - in jedem weiteren Teil: ab Byte 255 (direkt nach dem festen Header)
      - Endpunkt: im letzten beteiligten Teil bis start_integral_data,
        in jedem mittleren Teil bis dirs_list_offset (== header.dir_offset)
    """
    raw = bytearray()

    for part_id in range(entry.seq_first, entry.seq_last + 1):
        part = _get_part_retrying(header, part_id, on_missing_part)

        start = entry.comp_offset if part_id == entry.seq_first else HEADER_SIZE

        if part_id == entry.seq_last:
            end = part.start_integral_data
        else:
            end = part.dir_offset

        if end < start or end > len(part.data):
            raise IS3Error(
                "'%s': ungueltiger Datenbereich in Archivteil %d (start=%d, end=%d, Teilgroesse=%d)."
                % (entry.rel_path, part_id, start, end, len(part.data))
            )

        raw += part.data[start:end]

    return bytes(raw)


def extract_file(header: IS3Header, entry: FileEntry, out_path: str, on_missing_part=None):
    """Extrahiert einen FileEntry nach out_path.

    Ungueltige (geloeschte) Eintraege werden abgelehnt. Nicht
    komprimierte (entry.stored) Dateien werden roh kopiert statt durch
    blast_decompress() gejagt zu werden. Ueber mehrere Archivteile
    gesplittete Dateien (entry.partial) werden transparent
    zusammengelesen (siehe _gather_split_data()).

    on_missing_part: optionaler Callback fuer den Fall, dass ein
    benoetigter Archivteil (z.B. SETUP.2) nicht gefunden wird - z.B.
    weil die Teile auf verschiedenen Disketten/Datentraegern liegen.
    Signatur: on_missing_part(exc: IS3PartNotFoundError) -> bool
    (True = nach Registrierung eines Pfads erneut versuchen).
    """
    if entry.invalid:
        raise IS3Error("Datei '%s' ist als ungueltig markiert." % entry.rel_path)

    if entry.partial:
        raw = _gather_split_data(header, entry, on_missing_part)
    else:
        if entry.comp_offset + entry.comp_size > len(header.data):
            raise IS3Error(
                "'%s': Daten liegen ausserhalb der Datei "
                "(offset=%d, size=%d, Dateigroesse=%d)."
                % (entry.rel_path, entry.comp_offset, entry.comp_size, len(header.data))
            )
        raw = header.data[entry.comp_offset: entry.comp_offset + entry.comp_size]

    if entry.stored:
        # Nicht komprimiert - Rohdaten direkt uebernehmen, kein blast().
        decompressed = raw
    else:
        try:
            decompressed = blast_decompress(raw, max_out=entry.size)
        except BlastError as e:
            raise IS3Error("Dekompression von '%s' fehlgeschlagen: %s" % (entry.rel_path, e))

    if len(decompressed) != entry.size:
        raise IS3Error(
            "'%s': Groesse stimmt nicht - erwartet %d, erhalten %d Bytes."
            % (entry.rel_path, entry.size, len(decompressed))
        )

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(decompressed)
