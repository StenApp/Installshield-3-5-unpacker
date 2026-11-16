import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import blast  # noqa: E402
import is3  # noqa: E402


class _BitWriter:
    """Gegenstueck zum bits()-Leser in blast.py: packt Bits LSB-zuerst
    in Bytes, exakt wie das PKWare-DCL-Format es erwartet."""

    def __init__(self):
        self.out = bytearray()
        self.bitbuf = 0
        self.bitcnt = 0

    def write(self, value: int, nbits: int):
        self.bitbuf |= (value & ((1 << nbits) - 1)) << self.bitcnt
        self.bitcnt += nbits
        while self.bitcnt >= 8:
            self.out.append(self.bitbuf & 0xFF)
            self.bitbuf >>= 8
            self.bitcnt -= 8

    def flush(self) -> bytes:
        if self.bitcnt > 0:
            self.out.append(self.bitbuf & 0xFF)
            self.bitbuf = 0
            self.bitcnt = 0
        return bytes(self.out)


def _write_huffman_symbol(bw: _BitWriter, huff, symbol: int):
    """Schreibt den kanonischen Code fuer `symbol` gemaess huff, MSB
    zuerst aus dem Codewert, jedes Bit invertiert (Gegenstueck zu
    decode()'s `code |= bits(1) ^ 1`)."""
    table = blast._huffman_encode_table(huff)
    code, length = table[symbol]
    for i in range(length - 1, -1, -1):
        bit = (code >> i) & 1
        bw.write(bit ^ 1, 1)


def blast_compress_literals(data: bytes) -> bytes:
    """Baut einen gueltigen PKWare-DCL-Stream, der `data` als reine,
    unkodierte Literale kodiert (lit=0) - fuer Roundtrip-Tests ohne
    eigenen vollwertigen Compressor."""
    bw = _BitWriter()
    bw.write(0, 8)  # lit = 0 (Literale unkodiert)
    bw.write(4, 8)  # dict = 4 (beliebig, wird bei reinen Literalen nicht genutzt)

    for byte in data:
        bw.write(0, 1)          # Flag: Literal
        bw.write(byte, 8)       # unkodiertes Literal, normale Bitreihenfolge

    # Endcode: Flag=1 (Laenge/Distanz), lencode-Symbol 15 (base=264,
    # extra=8 Bits) mit extra=255 -> len = 264+255 = 519 = Endemarker
    bw.write(1, 1)
    _write_huffman_symbol(bw, blast._LENCODE, 15)
    bw.write(255, 8)

    return bw.flush()


def run_blast_reference_test():
    data = bytes.fromhex("0004822425 8f807f".replace(" ", ""))
    out = blast.blast_decompress(data)
    assert out == b"AIAIAIAIAIAIA", out
    print("OK blast: Referenz-Testvektor aus blast.c (Mark Adler) stimmt")


def run_blast_literal_roundtrip_test():
    for content in [
        b"",
        b"A",
        b"Hallo Welt!",
        bytes(range(256)),
        b"X" * 5000,  # laenger als MAXWIN(4096), prueft Distanz-Grenzen indirekt nicht,
                      # aber Robustheit bei grossen reinen Literal-Stroemen
    ]:
        compressed = blast_compress_literals(content)
        decompressed = blast.blast_decompress(compressed, max_out=len(content))
        assert decompressed == content, (
            "Blast-Literal-Roundtrip fehlgeschlagen bei %d Bytes" % len(content)
        )
    print("OK blast: Literal-Roundtrip (eigener Bit-Encoder) fuer mehrere Testinhalte")


def build_is3_archive(path, files, directory_name=""):
    """files: Liste von (name, content_bytes). Baut ein minimales,
    nicht gesplittetes IS3-Archiv mit einem Verzeichnis."""
    header = bytearray(is3.HEADER_SIZE)
    header[0:8] = is3.SIGNATURE

    dirname_b = directory_name.encode("latin-1")
    dir_entry = struct.pack("<HHBB", len(files), 0, len(dirname_b), 0) + dirname_b
    dir_entry_full = bytearray(dir_entry)
    struct.pack_into("<H", dir_entry_full, 2, len(dir_entry_full))  # hdrSize korrigieren

    dir_offset = len(header)
    body = bytearray(header)
    body += dir_entry_full

    file_offset = len(body)

    compressed_blobs = []
    file_entries = bytearray()
    running_comp_offset_placeholder = []

    for name, content in files:
        comp = blast_compress_literals(content)
        compressed_blobs.append(comp)

    # Erst alle File-Entries (mit Platzhalter-Offsets) schreiben, dann
    # die komprimierten Daten anhaengen und Offsets zurueckpatchen.
    entry_positions = []
    for (name, content), comp in zip(files, compressed_blobs):
        name_b = name.encode("latin-1")
        entry_start = len(body)
        entry = struct.pack(
            "<BHIIIIB3sHBBBB",
            0,                  # seqLast
            0,                  # directory (einziges Verzeichnis, Index 0)
            len(content),       # size
            len(comp),          # compSize
            0,                  # compOffset (Platzhalter, unten gepatcht)
            0,                  # datetime
            0,                  # attributes
            b"\x00\x00\x00",    # unknown1[3]
            0,                  # hdrSize (Platzhalter)
            0,                  # unknown2
            0,                  # partial
            0,                  # unknown3
            0,                  # seqFirst
        )
        entry = bytearray(entry)
        entry += struct.pack("<B", len(name_b)) + name_b
        struct.pack_into("<H", entry, 0x17, len(entry))  # hdrSize
        body += entry
        entry_positions.append(entry_start)

    for pos, comp in zip(entry_positions, compressed_blobs):
        comp_offset = len(body)
        body += comp
        struct.pack_into("<I", body, pos + 0x0B, comp_offset)

    archive_size = len(body)
    total_size = sum(len(c) for _, c in files)

    struct.pack_into("<H", body, 0x0C, len(files))       # numFiles
    struct.pack_into("<I", body, 0x0E, 0)                # datetime
    struct.pack_into("<I", body, 0x12, archive_size)      # archiveSize
    struct.pack_into("<I", body, 0x16, total_size)        # totalSize
    struct.pack_into("<I", body, 0x29, dir_offset)         # dirOffset
    struct.pack_into("<H", body, 0x31, 1)                  # directories
    struct.pack_into("<I", body, 0x33, file_offset)         # fileOffset

    with open(path, "wb") as f:
        f.write(body)

    return path


def run_is3_extraction_test():
    d = "/tmp/is3test"
    os.makedirs(d, exist_ok=True)

    files = [
        ("readme.txt", b"Dies ist eine Testdatei fuer den IS3-Parser.\n" * 5),
        ("data.bin", bytes(range(256)) * 3),
        ("leer.dat", b""),
    ]

    path = build_is3_archive(os.path.join(d, "data1.z"), files, directory_name="")
    header = is3.IS3Header(path)

    assert header.num_files == 3, header.num_files
    assert header.num_dirs == 1, header.num_dirs
    assert not header.split

    names = [fe.name for fe in header.files]
    assert names == ["readme.txt", "data.bin", "leer.dat"], names

    for fe, (expected_name, expected_content) in zip(header.files, files):
        assert fe.name == expected_name
        assert fe.size == len(expected_content)
        assert not fe.partial

        out_path = os.path.join(d, "out_" + fe.name.replace("/", "_"))
        is3.extract_file(header, fe, out_path)
        with open(out_path, "rb") as f:
            extracted = f.read()
        assert extracted == expected_content, (
            "IS3-Extraktion fehlerhaft fuer '%s': %d Bytes erhalten, %d erwartet"
            % (fe.name, len(extracted), len(expected_content))
        )

    print("OK is3: Header/Directory/File-Parsing + Extraktion fuer %d Dateien korrekt" % len(files))


def build_is3_archive_with_flags(path, files, directory_name=""):
    """Wie build_is3_archive(), aber `files` ist eine Liste von
    (name, content, flags) - flags nach FileEntry.FLAG_* (z.B.
    FLAG_STORED fuer unkomprimierte Dateien, FLAG_INVALID fuer
    geloeschte Eintraege). Bei FLAG_STORED wird der Inhalt NICHT
    komprimiert, sondern roh abgelegt. Bei FLAG_INVALID wird ein
    leerer Platzhalter abgelegt (Inhalt wird ignoriert)."""
    header = bytearray(is3.HEADER_SIZE)
    header[0:8] = is3.SIGNATURE

    dirname_b = directory_name.encode("latin-1")
    dir_entry = struct.pack("<HHBB", len(files), 0, len(dirname_b), 0) + dirname_b
    dir_entry_full = bytearray(dir_entry)
    struct.pack_into("<H", dir_entry_full, 2, len(dir_entry_full))

    dir_offset = len(header)
    body = bytearray(header)
    body += dir_entry_full

    file_offset = len(body)

    blobs = []
    for name, content, flags in files:
        if flags & is3.FileEntry.FLAG_INVALID:
            blobs.append(b"")
        elif flags & is3.FileEntry.FLAG_STORED:
            blobs.append(content)
        else:
            blobs.append(blast_compress_literals(content))

    entry_positions = []
    for (name, content, flags), blob in zip(files, blobs):
        name_b = name.encode("latin-1")
        entry_start = len(body)
        entry = struct.pack(
            "<BHIIIIB3sHHBBB",
            0,                          # seqLast
            0,                          # directory
            len(content),               # size
            len(blob),                  # compSize
            0,                          # compOffset (Platzhalter)
            0,                          # datetime
            0,                          # attributes
            b"\x00\x00\x00",            # unknown1[3]
            0,                          # hdrSize (Platzhalter)
            flags,                      # volles 16-Bit-Flags-Feld @0x19
            0,                          # unknown3 @0x1b
            0,                          # seqFirst @0x1c
            len(name_b),                # nameLength @0x1d
        )
        entry = bytearray(entry)
        entry += name_b
        struct.pack_into("<H", entry, 0x17, len(entry))
        body += entry
        entry_positions.append(entry_start)

    for pos, blob in zip(entry_positions, blobs):
        comp_offset = len(body)
        body += blob
        struct.pack_into("<I", body, pos + 0x0B, comp_offset)

    archive_size = len(body)
    total_size = sum(len(c) for _, c, _ in files)

    struct.pack_into("<H", body, 0x0C, len(files))
    struct.pack_into("<I", body, 0x0E, 0)
    struct.pack_into("<I", body, 0x12, archive_size)
    struct.pack_into("<I", body, 0x16, total_size)
    struct.pack_into("<I", body, 0x29, dir_offset)
    struct.pack_into("<H", body, 0x31, 1)
    struct.pack_into("<I", body, 0x33, file_offset)

    with open(path, "wb") as f:
        f.write(body)

    return path


def run_is3_stored_and_invalid_test():
    d = "/tmp/is3flagstest"
    os.makedirs(d, exist_ok=True)

    stored_content = b"Diese Datei ist NICHT komprimiert, einfach roh.\n" * 10
    compressed_content = b"Diese Datei ist ganz normal komprimiert.\n" * 10

    files = [
        ("stored.bin", stored_content, is3.FileEntry.FLAG_STORED),
        ("normal.bin", compressed_content, 0),
        ("deleted.bin", b"wird ignoriert", is3.FileEntry.FLAG_INVALID),
    ]

    path = build_is3_archive_with_flags(d + "/flags1.z", files)
    header = is3.IS3Header(path)
    assert header.num_files == 3

    fe_stored, fe_normal, fe_deleted = header.files
    assert fe_stored.stored is True
    assert fe_stored.invalid is False
    assert fe_normal.stored is False
    assert fe_normal.invalid is False
    assert fe_deleted.invalid is True

    out_stored = os.path.join(d, "out_stored.bin")
    is3.extract_file(header, fe_stored, out_stored)
    with open(out_stored, "rb") as f:
        assert f.read() == stored_content
    print("OK is3: stored (unkomprimierte) Datei korrekt roh kopiert, nicht durch blast() gejagt")

    out_normal = os.path.join(d, "out_normal.bin")
    is3.extract_file(header, fe_normal, out_normal)
    with open(out_normal, "rb") as f:
        assert f.read() == compressed_content
    print("OK is3: normale komprimierte Datei weiterhin korrekt")

    try:
        is3.extract_file(header, fe_deleted, os.path.join(d, "should_not_exist.bin"))
        raise AssertionError("geloeschter Eintrag haette abgelehnt werden muessen")
    except is3.IS3Error as e:
        print("OK is3: ungueltiger (geloeschter) Eintrag korrekt abgelehnt (%s)" % e)


def build_is3_split_archive(dir_path, split_content: bytes, split_at: int):
    """Baut ein 2-teiliges IS3-Split-Archiv (SETUP.Z + SETUP.2), bei dem
    genau EINE Datei physisch ueber die Teil-Grenze hinweg gesplittet
    ist - Layout nach idecomp.py: Rohdaten kommen VOR der Verzeichnis-/
    Dateiliste, Teil 2 traegt ab Byte 255 die Fortsetzung."""
    comp = blast_compress_literals(split_content)
    assert 0 < split_at < len(comp), "split_at liegt ausserhalb der Payload"
    part1_data = comp[:split_at]
    part2_data = comp[split_at:]

    name = "split.dat"
    name_b = name.encode("latin-1")

    # --- Teil 1: Header + Rohdaten (part1_data) + Verzeichnis-/Dateiliste ---
    header1 = bytearray(is3.HEADER_SIZE)
    header1[0:8] = is3.SIGNATURE

    body1 = bytearray(header1)
    comp_offset = len(body1)
    body1 += part1_data

    dir_offset1 = len(body1)
    dirname_b = b""
    dir_entry = struct.pack("<HHBB", 1, 0, 0, 0) + dirname_b
    dir_entry = bytearray(dir_entry)
    struct.pack_into("<H", dir_entry, 2, len(dir_entry))
    body1 += dir_entry

    file_offset1 = len(body1)
    entry_flags = is3.FileEntry.FLAG_SPLIT
    entry = struct.pack(
        "<BHIIIIB3sHHBBB",
        2,                    # seqLast = Teil, in dem die Datei ENDET
        0,                    # directory
        len(split_content),   # size
        len(comp),            # compSize (GESAMT ueber beide Teile)
        comp_offset,          # compOffset (in Teil 1)
        0, 0, b"\x00\x00\x00",
        0,                    # hdrSize (Platzhalter)
        entry_flags,          # flags @0x19 (FLAG_SPLIT gesetzt)
        0,                    # unknown3
        1,                    # seqFirst = Teil, in dem die Datei BEGINNT
        len(name_b),
    )
    entry = bytearray(entry)
    entry += name_b
    struct.pack_into("<H", entry, 0x17, len(entry))
    body1 += entry

    archive_size1 = len(body1)
    struct.pack_into("<H", body1, 0x0C, 1)                 # numFiles
    struct.pack_into("<I", body1, 0x12, archive_size1)      # archiveSize
    struct.pack_into("<I", body1, 0x16, len(split_content)) # totalSize
    struct.pack_into("<I", body1, 0x29, dir_offset1)        # dirOffset
    struct.pack_into("<H", body1, 0x31, 1)                  # numDirs
    struct.pack_into("<I", body1, 0x33, file_offset1)       # fileOffset
    # Split-Flags im Header (Offset 0x0a) + splitFiles/curSeq (0x1e/0x1f)
    struct.pack_into("<H", body1, 0x0A, is3.FLAG_SPLIT)
    struct.pack_into("<B", body1, 0x1E, 2)   # num_split (Gesamtzahl Teile)
    struct.pack_into("<B", body1, 0x1F, 1)   # cur_seq (dies ist Teil 1)
    # start_integral_data (0x25) fuer Teil 1 wird nicht genutzt (Teil 1
    # ist hier nie der LETZTE beteiligte Teil), aber sinnvoll befuellen:
    struct.pack_into("<I", body1, 0x25, dir_offset1)

    path1 = os.path.join(dir_path, "SETUP.Z")
    with open(path1, "wb") as f:
        f.write(body1)

    # --- Teil 2: Header + Rohdaten (part2_data), KEINE eigenen Dateien ---
    header2 = bytearray(is3.HEADER_SIZE)
    header2[0:8] = is3.SIGNATURE

    body2 = bytearray(header2)
    body2 += part2_data
    start_integral_data2 = len(body2)  # keine weiteren kompletten Dateien danach
    dir_offset2 = len(body2)
    body2 += b"\x00" * 4  # winziger Puffer, damit dir_offset < archive_size

    archive_size2 = len(body2)
    struct.pack_into("<H", body2, 0x0C, 0)                  # numFiles = 0
    struct.pack_into("<I", body2, 0x12, archive_size2)
    struct.pack_into("<I", body2, 0x16, 0)
    struct.pack_into("<I", body2, 0x29, dir_offset2)
    struct.pack_into("<H", body2, 0x31, 0)                  # numDirs = 0
    struct.pack_into("<I", body2, 0x33, dir_offset2)        # fileOffset (0 Dateien)
    struct.pack_into("<H", body2, 0x0A, is3.FLAG_SPLIT)
    struct.pack_into("<B", body2, 0x1E, 2)
    struct.pack_into("<B", body2, 0x1F, 2)   # cur_seq (dies ist Teil 2)
    struct.pack_into("<I", body2, 0x25, start_integral_data2)

    path2 = os.path.join(dir_path, "SETUP.2")
    with open(path2, "wb") as f:
        f.write(body2)

    return path1


def run_is3_split_extraction_test():
    """Prueft, dass extract_file() eine Datei, die physisch ueber zwei
    IS3-Archivteile (SETUP.Z/SETUP.2) verteilt ist, korrekt und
    vollstaendig zusammenliest."""
    d = "/tmp/is3split"
    os.makedirs(d, exist_ok=True)

    content = (b"Laengerer Testinhalt fuer den IS3-Split-Test, damit der "
               b"komprimierte Chunk gross genug ist, um sauber mitten "
               b"entzwei geschnitten zu werden.\n") * 15

    comp_len = len(blast_compress_literals(content))
    split_at = comp_len // 2

    path1 = build_is3_split_archive(d, content, split_at)
    header = is3.IS3Header(path1)

    assert header.split is True
    assert header.num_split == 2
    assert header.cur_seq == 1
    assert header.num_files == 1

    fe = header.files[0]
    assert fe.name == "split.dat"
    assert fe.partial is True
    assert fe.seq_first == 1
    assert fe.seq_last == 2

    out_path = os.path.join(d, "out_split.dat")
    is3.extract_file(header, fe, out_path)

    with open(out_path, "rb") as f:
        extracted = f.read()

    assert extracted == content, (
        "IS3-Split-Extraktion fehlerhaft: %d Bytes erhalten, %d erwartet"
        % (len(extracted), len(content))
    )
    print(
        "OK is3-Split: %d Bytes korrekt ueber SETUP.Z -> SETUP.2 zusammengelesen"
        % len(extracted)
    )


def run_is3_split_missing_part_test():
    """Prueft den on_missing_part-Callback: SETUP.2 fehlt zunaechst,
    wird erst im Callback bereitgestellt (Disketten-Wechsel-Simulation)."""
    d = "/tmp/is3split_missing"
    os.makedirs(d, exist_ok=True)
    hidden_dir = "/tmp/is3split_disk2"
    os.makedirs(hidden_dir, exist_ok=True)

    content = b"Diskettenwechsel-Simulation fuer IS3-Split.\n" * 20
    comp_len = len(blast_compress_literals(content))
    split_at = comp_len // 2

    path1 = build_is3_split_archive(d, content, split_at)

    # SETUP.2 verstecken (simuliert: Diskette 2 noch nicht eingelegt)
    real_part2 = os.path.join(d, "SETUP.2")
    hidden_part2 = os.path.join(hidden_dir, "SETUP.2")
    os.replace(real_part2, hidden_part2)

    header = is3.IS3Header(path1)
    fe = header.files[0]

    calls = [0]

    def on_missing_part(e):
        calls[0] += 1
        assert e.part_id == 2
        header.register_part_path(2, hidden_part2)
        return True

    out_path = os.path.join(d, "out_missing.dat")
    is3.extract_file(header, fe, out_path, on_missing_part=on_missing_part)

    with open(out_path, "rb") as f:
        extracted = f.read()
    assert extracted == content
    assert calls[0] == 1
    print("OK is3-Split: fehlender Teil (SETUP.2) per Callback nachgereicht, Ergebnis korrekt")


if __name__ == "__main__":
    run_blast_reference_test()
    run_blast_literal_roundtrip_test()
    run_is3_extraction_test()
    run_is3_stored_and_invalid_test()
    run_is3_split_extraction_test()
    run_is3_split_missing_part_test()
    print("Alle IS3-Selbsttests bestanden.")
