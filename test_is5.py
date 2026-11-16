import os
import struct
import zlib
import sys

sys.path.insert(0, os.path.dirname(__file__))
import is5  # noqa: E402


def _compress_chunk(content: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(content) + co.flush()


def _obfuscate(payload: bytes) -> bytes:
    """Umkehrung von is5._deobfuscate(): sub -> rol -> xor
    (statt xor -> ror -> sub beim Entschluesseln)."""
    obf = bytearray()
    s = 0
    for b in payload:
        b = (b + (s % 0x47)) & 0xFF
        b = ((b << 2) | (b >> 6)) & 0xFF  # rol8 by 2, Umkehrung von ror8
        b = b ^ 0xD5
        obf.append(b)
        s += 1
    return bytes(obf)


def _write_volume_header_v5(buf, offset, *, first_file_index, last_file_index,
                             first_size_exp, first_size_comp,
                             last_size_exp, last_size_comp):
    """Schreibt die 40-Byte V5-Volume-Header-Struktur ab `offset`."""
    struct.pack_into(
        "<10I", buf, offset,
        0,                  # data_offset (ungenutzt in unseren Tests)
        0,                  # unknown
        first_file_index,
        last_file_index,
        0,                  # first_file_offset (ungenutzt, kein Split)
        first_size_exp,
        first_size_comp,
        0,                  # last_file_offset (ungenutzt, kein Split)
        last_size_exp,
        last_size_comp,
    )


def build_single_volume_cab(path, content: bytes, obfuscate=False):
    """Ein Volume, ein File - Header und Daten in derselben Datei
    (kein separates .hdr)."""
    version = (1 << 24) | (5 << 12)  # -> major_version == 5

    cab_descriptor_offset = 60  # nach common header(20) + volume header(40)
    file_table_offset = 0x30    # relativ zu cab_descriptor_offset
    base = cab_descriptor_offset + file_table_offset

    dir_off_rel = 8
    filedesc_off_rel = 16
    name_off_rel = 16 + 0x3A

    filename = b"test.txt\x00"
    dirname = b"\x00"

    chunk = _compress_chunk(content)
    compressed_size = 2 + len(chunk)
    payload = struct.pack("<H", len(chunk)) + chunk
    if obfuscate:
        payload = _obfuscate(payload)

    data_offset = base + name_off_rel + len(filename) + 16  # etwas Puffer

    buf = bytearray(data_offset + len(payload))

    struct.pack_into("<5I", buf, 0,
                      is5.CAB_SIGNATURE, version, 0, cab_descriptor_offset, 0x30)

    _write_volume_header_v5(
        buf, 20,
        first_file_index=0, last_file_index=0,
        first_size_exp=len(content), first_size_comp=compressed_size,
        last_size_exp=len(content), last_size_comp=compressed_size,
    )

    p = cab_descriptor_offset + 0xC
    struct.pack_into("<I", buf, p, file_table_offset); p += 8
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 1); p += 4   # directory_count
    p += 8
    struct.pack_into("<I", buf, p, 1); p += 4   # file_count
    struct.pack_into("<I", buf, p, 0); p += 4

    struct.pack_into("<I", buf, base + 0, dir_off_rel)
    struct.pack_into("<I", buf, base + 4, filedesc_off_rel)

    buf[base + dir_off_rel: base + dir_off_rel + len(dirname)] = dirname

    fp = base + filedesc_off_rel
    struct.pack_into("<I", buf, fp, name_off_rel); fp += 4
    struct.pack_into("<H", buf, fp, 0); fp += 2
    fp += 2
    flags = is5.FILE_COMPRESSED | (is5.FILE_OBFUSCATED if obfuscate else 0)
    struct.pack_into("<H", buf, fp, flags); fp += 2
    struct.pack_into("<I", buf, fp, len(content)); fp += 4
    struct.pack_into("<I", buf, fp, compressed_size); fp += 4
    fp += 0x14
    struct.pack_into("<I", buf, fp, data_offset); fp += 4
    fp += 0x10
    assert fp - (base + filedesc_off_rel) == 0x3A

    buf[base + name_off_rel: base + name_off_rel + len(filename)] = filename
    buf[data_offset: data_offset + len(payload)] = payload

    with open(path, "wb") as f:
        f.write(buf)


def run_single_volume_test(obfuscate):
    path = "/tmp/synth_single.cab"
    content = b"Hallo Welt! Dies ist ein Testinhalt fuer den ISCab-Parser.\n" * 3
    build_single_volume_cab(path, content, obfuscate=obfuscate)

    header = is5.ISCabHeader(path)
    assert header.major_version == 5
    assert header.directory_count == 1
    assert header.file_count == 1

    fe = header.files[0]
    assert fe.name == "test.txt"
    assert fe.expanded_size == len(content)
    assert fe.compressed is True
    assert fe.obfuscated == obfuscate

    out_path = "/tmp/synth_single_out.txt"
    is5.extract_file(header, fe, out_path)

    with open(out_path, "rb") as f:
        extracted = f.read()

    assert extracted == content, "Inhalt stimmt nicht: %r != %r" % (extracted, content)
    print("OK Single-Volume (obfuscate=%s): %d Bytes korrekt" % (obfuscate, len(extracted)))


def build_two_volume_cabs(dir_path, content0: bytes, content1: bytes):
    """data1.cab: Header (2 Dateien) + Daten von file0.
       data2.cab: nur Daten von file1 (kein Header/Cab-Descriptor)."""
    version = (1 << 24) | (5 << 12)

    cab_descriptor_offset = 60
    file_table_offset = 0x30
    base = cab_descriptor_offset + file_table_offset

    # File-Table hat hier 3 Eintraege (1 Verzeichnis + 2 Dateien) = 12 Bytes
    # (rel 0..12) - der Directory-Name darf daher erst danach beginnen.
    dir_off_rel = 12
    fd0_off_rel = 16
    fd1_off_rel = 16 + 0x3A
    name0_off_rel = fd1_off_rel + 0x3A
    filename0 = b"first.bin\x00"
    name1_off_rel = name0_off_rel + len(filename0)
    filename1 = b"second.bin\x00"
    dirname = b"\x00"

    chunk0 = _compress_chunk(content0)
    comp_size0 = 2 + len(chunk0)
    payload0 = struct.pack("<H", len(chunk0)) + chunk0

    chunk1 = _compress_chunk(content1)
    comp_size1 = 2 + len(chunk1)
    payload1 = struct.pack("<H", len(chunk1)) + chunk1

    data_offset0 = base + name1_off_rel + len(filename1) + 16

    buf1 = bytearray(data_offset0 + len(payload0))
    struct.pack_into("<5I", buf1, 0,
                      is5.CAB_SIGNATURE, version, 0, cab_descriptor_offset, 0x30)

    # Volume 1 enthaelt nur file-index 0
    _write_volume_header_v5(
        buf1, 20,
        first_file_index=0, last_file_index=0,
        first_size_exp=len(content0), first_size_comp=comp_size0,
        last_size_exp=len(content0), last_size_comp=comp_size0,
    )

    p = cab_descriptor_offset + 0xC
    struct.pack_into("<I", buf1, p, file_table_offset); p += 8
    struct.pack_into("<I", buf1, p, 0x30); p += 4
    struct.pack_into("<I", buf1, p, 0x30); p += 4
    struct.pack_into("<I", buf1, p, 1); p += 4   # directory_count
    p += 8
    struct.pack_into("<I", buf1, p, 2); p += 4   # file_count = 2!
    struct.pack_into("<I", buf1, p, 0); p += 4

    struct.pack_into("<I", buf1, base + 0, dir_off_rel)
    struct.pack_into("<I", buf1, base + 4, fd0_off_rel)
    struct.pack_into("<I", buf1, base + 8, fd1_off_rel)

    buf1[base + dir_off_rel: base + dir_off_rel + len(dirname)] = dirname

    fp = base + fd0_off_rel
    struct.pack_into("<I", buf1, fp, name0_off_rel); fp += 4
    struct.pack_into("<H", buf1, fp, 0); fp += 2
    fp += 2
    struct.pack_into("<H", buf1, fp, is5.FILE_COMPRESSED); fp += 2
    struct.pack_into("<I", buf1, fp, len(content0)); fp += 4
    struct.pack_into("<I", buf1, fp, comp_size0); fp += 4
    fp += 0x14
    struct.pack_into("<I", buf1, fp, data_offset0); fp += 4
    fp += 0x10
    assert fp - (base + fd0_off_rel) == 0x3A

    fp = base + fd1_off_rel
    struct.pack_into("<I", buf1, fp, name1_off_rel); fp += 4
    struct.pack_into("<H", buf1, fp, 0); fp += 2
    fp += 2
    struct.pack_into("<H", buf1, fp, is5.FILE_COMPRESSED); fp += 2
    struct.pack_into("<I", buf1, fp, len(content1)); fp += 4
    struct.pack_into("<I", buf1, fp, comp_size1); fp += 4
    fp += 0x14
    data_offset1 = 60  # in data2.cab, direkt nach common+volume header
    struct.pack_into("<I", buf1, fp, data_offset1); fp += 4
    fp += 0x10
    assert fp - (base + fd1_off_rel) == 0x3A

    buf1[base + name0_off_rel: base + name0_off_rel + len(filename0)] = filename0
    buf1[base + name1_off_rel: base + name1_off_rel + len(filename1)] = filename1
    buf1[data_offset0: data_offset0 + len(payload0)] = payload0

    path1 = os.path.join(dir_path, "mvtest1.cab")
    with open(path1, "wb") as f:
        f.write(buf1)

    # Volume 2: nur common header + volume header (first/last file index=1) + Daten
    buf2 = bytearray(data_offset1 + len(payload1))
    struct.pack_into("<5I", buf2, 0,
                      is5.CAB_SIGNATURE, version, 0, 0, 0)  # Descriptor hier irrelevant
    _write_volume_header_v5(
        buf2, 20,
        first_file_index=1, last_file_index=1,
        first_size_exp=len(content1), first_size_comp=comp_size1,
        last_size_exp=len(content1), last_size_comp=comp_size1,
    )
    buf2[data_offset1: data_offset1 + len(payload1)] = payload1

    path2 = os.path.join(dir_path, "mvtest2.cab")
    with open(path2, "wb") as f:
        f.write(buf2)

    return path1


def run_multi_volume_test():
    d = "/tmp/mvtest"
    os.makedirs(d, exist_ok=True)
    content0 = b"Inhalt der ersten Datei, liegt komplett in Volume 1.\n" * 2
    content1 = b"Inhalt der zweiten Datei, liegt komplett in Volume 2 (data2.cab).\n" * 2

    path1 = build_two_volume_cabs(d, content0, content1)

    header = is5.ISCabHeader(path1)
    assert header.file_count == 2
    fe0, fe1 = header.files

    assert fe0.name == "first.bin"
    assert fe1.name == "second.bin"

    volume0, vh0 = header.resolve_volume(fe0)
    volume1, vh1 = header.resolve_volume(fe1)
    assert volume0 == 1, "file0 sollte in Volume 1 liegen, war %r" % volume0
    assert volume1 == 2, "file1 sollte in Volume 2 aufgeloest werden, war %r" % volume1
    assert os.path.basename(vh1["path"]).lower() == "mvtest2.cab"

    out0 = os.path.join(d, "out_first.bin")
    out1 = os.path.join(d, "out_second.bin")
    is5.extract_file(header, fe0, out0)
    is5.extract_file(header, fe1, out1)

    with open(out0, "rb") as f:
        assert f.read() == content0
    with open(out1, "rb") as f:
        assert f.read() == content1

    print("OK Multi-Volume: file0 korrekt aus Volume 1, file1 korrekt aus Volume 2 (data2.cab) extrahiert")



class _Arena:
    """Hilfsklasse fuer den Testbuilder: haengt Bytes an einen Buffer an
    und merkt sich Offsets, um Konstruktionsfehler durch manuelle
    Offset-Arithmetik (wie den vorherigen dir_off_rel-Bug) zu vermeiden."""

    def __init__(self, initial_size):
        self.buf = bytearray(initial_size)

    def add(self, data: bytes) -> int:
        off = len(self.buf)
        self.buf += data
        return off

    def reserve(self, n: int) -> int:
        off = len(self.buf)
        self.buf += bytes(n)
        return off


def build_split_file_cabs(dir_path, content_head: bytes, content_split: bytes,
                           content_tail: bytes, split_at: int):
    """3 Dateien: head.bin (ganz in Volume 1), split.bin (physisch ueber
    die Volume-1/2-Grenze bei Byte `split_at` geteilt), tail.bin (ganz
    in Volume 2). Damit werden beide Guards aus dem Original-Code
    (index < file_count-1 und index > 0) korrekt erfuellt."""
    version = (1 << 24) | (5 << 12)

    cab_descriptor_offset = 60
    file_table_offset = 0x30
    base = cab_descriptor_offset + file_table_offset  # 108

    directory_count = 1
    file_count = 3

    arena = _Arena(base)  # arena.buf[0:base] ist noch leer/Platzhalter

    file_table_rel = arena.reserve((directory_count + file_count) * 4) - base
    dir_rel = arena.add(b"\x00") - base
    fd0_rel = arena.reserve(0x3A) - base
    fd1_rel = arena.reserve(0x3A) - base
    fd2_rel = arena.reserve(0x3A) - base
    name0_rel = arena.add(b"head.bin\x00") - base
    name1_rel = arena.add(b"split.bin\x00") - base
    name2_rel = arena.add(b"tail.bin\x00") - base

    struct.pack_into("<4I", arena.buf, base + file_table_rel,
                      dir_rel, fd0_rel, fd1_rel, fd2_rel)

    chunk_head = _compress_chunk(content_head)
    payload_head = struct.pack("<H", len(chunk_head)) + chunk_head

    chunk_split = _compress_chunk(content_split)
    payload_split = struct.pack("<H", len(chunk_split)) + chunk_split
    assert 0 < split_at < len(payload_split), "split_at liegt ausserhalb der Payload"
    part1 = payload_split[:split_at]
    part2 = payload_split[split_at:]

    chunk_tail = _compress_chunk(content_tail)
    payload_tail = struct.pack("<H", len(chunk_tail)) + chunk_tail

    # --- Daten in Volume 1: head.bin (vollstaendig) + part1 von split.bin ---
    data_off_head = len(arena.buf)
    arena.add(payload_head)
    data_off_split1 = len(arena.buf)
    arena.add(part1)

    buf1 = arena.buf
    struct.pack_into("<5I", buf1, 0,
                      is5.CAB_SIGNATURE, version, 0, cab_descriptor_offset, 0x30)

    _write_volume_header_v5(
        buf1, 20,
        first_file_index=0, last_file_index=1,
        first_size_exp=len(content_head), first_size_comp=len(payload_head),
        last_size_exp=len(content_split), last_size_comp=len(part1),
    )
    struct.pack_into("<I", buf1, 20 + 7 * 4, data_off_split1)  # last_file_offset

    p = cab_descriptor_offset + 0xC
    struct.pack_into("<I", buf1, p, file_table_offset); p += 8
    struct.pack_into("<I", buf1, p, 0x30); p += 4
    struct.pack_into("<I", buf1, p, 0x30); p += 4
    struct.pack_into("<I", buf1, p, directory_count); p += 4
    p += 8
    struct.pack_into("<I", buf1, p, file_count); p += 4
    struct.pack_into("<I", buf1, p, 0); p += 4

    def write_fd(rel, name_rel, flags, expanded_size, compressed_size, data_offset):
        fp = base + rel
        struct.pack_into("<I", buf1, fp, name_rel); fp += 4
        struct.pack_into("<H", buf1, fp, 0); fp += 2  # directory_index
        fp += 2
        struct.pack_into("<H", buf1, fp, flags); fp += 2
        struct.pack_into("<I", buf1, fp, expanded_size); fp += 4
        struct.pack_into("<I", buf1, fp, compressed_size); fp += 4
        fp += 0x14
        struct.pack_into("<I", buf1, fp, data_offset); fp += 4
        fp += 0x10
        assert fp - (base + rel) == 0x3A

    write_fd(fd0_rel, name0_rel, is5.FILE_COMPRESSED,
              len(content_head), len(payload_head), data_off_head)
    write_fd(fd1_rel, name1_rel, is5.FILE_COMPRESSED,
              len(content_split), len(payload_split), data_off_split1)  # nur fuer Nicht-Split-Fallback relevant
    write_fd(fd2_rel, name2_rel, is5.FILE_COMPRESSED,
              len(content_tail), len(payload_tail), 0)  # data_offset unten in Volume 2 gepatcht

    path1 = os.path.join(dir_path, "sptest1.cab")
    with open(path1, "wb") as f:
        f.write(buf1)

    # --- Volume 2: part2 von split.bin + tail.bin (vollstaendig) ---
    buf2 = bytearray(60)
    data_off_split2 = len(buf2)
    buf2 += part2
    data_off_tail = len(buf2)
    buf2 += payload_tail

    struct.pack_into("<5I", buf2, 0, is5.CAB_SIGNATURE, version, 0, 0, 0)
    _write_volume_header_v5(
        buf2, 20,
        first_file_index=1, last_file_index=2,
        first_size_exp=len(content_split), first_size_comp=len(part2),
        last_size_exp=len(content_tail), last_size_comp=len(payload_tail),
    )
    struct.pack_into("<I", buf2, 20 + 4 * 4, data_off_split2)  # first_file_offset

    path2 = os.path.join(dir_path, "sptest2.cab")
    with open(path2, "wb") as f:
        f.write(buf2)

    # tail.bin's data_offset (normaler, nicht-Split-Pfad) nachtraeglich in
    # buf1 patchen - relevant, weil fuer tail.bin (index==file_count-1)
    # der Split-Guard "index < file_count-1" nicht greift und stattdessen
    # der normale data_offset-Pfad genutzt wird:
    with open(path1, "r+b") as f:
        fp = base + fd2_rel + 4 + 2 + 2 + 2 + 4 + 4 + 0x14  # Position des data_offset-Feldes
        f.seek(fp)
        f.write(struct.pack("<I", data_off_tail))

    return path1


def run_split_extraction_test():
    """Prueft, dass extract_file() eine Datei, deren komprimierte
    Payload absichtlich MITTEN IM Kompressions-Chunk auf zwei Volumes
    verteilt ist, korrekt und vollstaendig zusammenliest - und dass
    die unbeteiligten Nachbardateien (nicht gesplittet) ebenfalls aus
    dem jeweils richtigen Volume korrekt extrahiert werden."""
    d = "/tmp/sptest"
    os.makedirs(d, exist_ok=True)

    content_head = b"Kopf-Datei, komplett in Volume 1.\n" * 3
    content_split = (b"Das ist ein laengerer Testinhalt, damit der komprimierte "
                      b"Chunk gross genug ist, um sauber mitten entzwei geschnitten "
                      b"zu werden.\n") * 20
    content_tail = b"Schluss-Datei, komplett in Volume 2.\n" * 3

    chunk = _compress_chunk(content_split)
    payload_len = 2 + len(chunk)
    split_at = payload_len // 2

    path1 = build_split_file_cabs(d, content_head, content_split, content_tail, split_at)
    header = is5.ISCabHeader(path1)
    assert header.file_count == 3

    fe_head, fe_split, fe_tail = header.files
    assert fe_head.name == "head.bin"
    assert fe_split.name == "split.bin"
    assert fe_tail.name == "tail.bin"

    vol_head, _ = header.resolve_volume(fe_head)
    vol_split, _ = header.resolve_volume(fe_split)
    vol_tail, _ = header.resolve_volume(fe_tail)
    assert vol_head == 1
    assert vol_split == 1  # Startvolume der gesplitteten Datei
    assert vol_tail == 2

    out_head = os.path.join(d, "out_head.bin")
    out_split = os.path.join(d, "out_split.bin")
    out_tail = os.path.join(d, "out_tail.bin")

    is5.extract_file(header, fe_head, out_head)
    is5.extract_file(header, fe_split, out_split)
    is5.extract_file(header, fe_tail, out_tail)

    with open(out_head, "rb") as f:
        assert f.read() == content_head
    with open(out_split, "rb") as f:
        extracted_split = f.read()
    with open(out_tail, "rb") as f:
        assert f.read() == content_tail

    assert extracted_split == content_split, (
        "Cross-Volume-Extraktion fehlerhaft: %d Bytes erhalten, %d erwartet"
        % (len(extracted_split), len(content_split))
    )
    print(
        "OK Split-Extraktion: head.bin (Vol.1), tail.bin (Vol.2) korrekt, "
        "split.bin (%d Bytes) korrekt ueber Volume-Grenze bei Payload-Byte %d/%d zusammengelesen"
        % (len(extracted_split), split_at, payload_len)
    )


def run_cd_swap_test():
    """Simuliert den Fall, dass data2.cab NICHT verfuegbar ist, wenn die
    Extraktion beginnt (z.B. weil nur CD 1 eingelegt ist), und erst
    waehrend des Lesens - via on_missing_volume-Callback - bereitgestellt
    wird ("CD gewechselt"). Prueft zusaetzlich, dass data1.cab dabei nur
    EINMAL geoeffnet wird (kein Neustart/erneutes Lesen von Volume 1)."""
    d = "/tmp/cdswap"
    os.makedirs(d, exist_ok=True)

    content_head = b"Kopf-Datei, komplett in Volume 1.\n" * 3
    content_split = (b"Laengerer Inhalt, der sauber ueber die Volume-Grenze "
                      b"geschnitten wird, um den CD-Wechsel-Callback mitten "
                      b"im Chunk auszuloesen.\n") * 20
    content_tail = b"Schluss-Datei, komplett in Volume 2.\n" * 3

    chunk = _compress_chunk(content_split)
    payload_len = 2 + len(chunk)
    split_at = payload_len // 2

    path1 = build_split_file_cabs(d, content_head, content_split, content_tail, split_at)

    # data2.cab aus dem Ordner entfernen ("CD 2 ist noch nicht eingelegt")
    # und an einen anderen Ort verschieben, wo es erst der Callback
    # findet - simuliert exakt "CD getauscht".
    hidden_dir = "/tmp/cdswap_cd2"
    os.makedirs(hidden_dir, exist_ok=True)
    real_data2 = os.path.join(d, "sptest2.cab")
    hidden_data2 = os.path.join(hidden_dir, "sptest2.cab")
    os.replace(real_data2, hidden_data2)

    header = is5.ISCabHeader(path1)  # liest die Datei einmal fuer den Header - VOR dem Zaehlen
    fe_head, fe_split, fe_tail = header.files

    open_calls = []
    real_open = open

    def counting_open(path, *a, **kw):
        if os.path.basename(path).lower() == "sptest1.cab":
            open_calls.append(path)
        return real_open(path, *a, **kw)

    import builtins
    calls_to_callback = [0]

    def on_missing_volume(e):
        calls_to_callback[0] += 1
        assert e.volume_index == 2
        assert e.filename.lower() == "sptest2.cab"
        header.register_volume_path(e.volume_index, hidden_data2)
        return True

    builtins.open = counting_open
    try:
        out_split = os.path.join(d, "out_split_cdswap.bin")
        is5.extract_file(header, fe_split, out_split, on_missing_volume=on_missing_volume)
    finally:
        builtins.open = real_open

    with open(out_split, "rb") as f:
        extracted = f.read()
    assert extracted == content_split, "CD-Wechsel-Extraktion lieferte falschen Inhalt"
    assert calls_to_callback[0] == 1, "Callback haette genau einmal aufgerufen werden muessen"
    # sptest1.cab wird legitim zweimal geoeffnet (einmal in
    # _get_volume_header() fuer die Volume-Header-Felder, einmal in
    # _open_volume_for_read() fuer den eigentlichen Datenstream) - das ist
    # kein Bug. Worauf es ankommt: es bleibt bei diesen zwei, es wird NICHT
    # nochmal geoeffnet, nachdem der Callback Volume 2 bereitgestellt hat
    # (das waere das Zeichen fuer einen Neustart von vorne).
    assert len(open_calls) <= 2, (
        "sptest1.cab wurde %d mal geoeffnet (erwartet: <=2) - sieht nach "
        "einem unnoetigen Neustart/erneuten Lesen von Volume 1 aus!" % len(open_calls)
    )

    print(
        "OK CD-Wechsel-Simulation: data2.cab war anfangs nicht da, wurde per "
        "Callback nachgereicht, data1.cab genau 1x geoeffnet (kein Neustart), "
        "Ergebnis (%d Bytes) korrekt" % len(extracted)
    )


def build_archive_with_corrupt_invalid_entry(path, valid_content: bytes):
    """Baut ein Archiv mit 2 Dateien: file0 normal/gueltig, file1 als
    FILE_INVALID markiert MIT einem Datenmuell-name_offset (weit ausserhalb
    der Datei) - genau das Muster, das frueher beim Laden des GESAMTEN
    Archivs mit einem rohen ValueError abgestuerzt ist (siehe
    _read_cstr()/_read_entry_name())."""
    version = (1 << 24) | (5 << 12)
    cab_descriptor_offset = 60
    file_table_offset = 0x30
    base = cab_descriptor_offset + file_table_offset

    dir_off_rel = 12  # 3 file_table-Eintraege (1 dir + 2 files) = 12 Bytes
    fd0_off_rel = 16
    fd1_off_rel = 16 + 0x3A
    name0_off_rel = fd1_off_rel + 0x3A
    filename0 = b"gut.txt\x00"
    dirname = b"\x00"

    chunk = _compress_chunk(valid_content)
    payload0 = struct.pack("<H", len(chunk)) + chunk

    data_offset0 = base + name0_off_rel + len(filename0) + 8

    buf = bytearray(data_offset0 + len(payload0))
    struct.pack_into("<5I", buf, 0,
                      is5.CAB_SIGNATURE, version, 0, cab_descriptor_offset, 0x30)
    _write_volume_header_v5(
        buf, 20,
        first_file_index=0, last_file_index=1,
        first_size_exp=0, first_size_comp=0,
        last_size_exp=0, last_size_comp=0,
    )

    p = cab_descriptor_offset + 0xC
    struct.pack_into("<I", buf, p, file_table_offset); p += 8
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 1); p += 4   # directory_count
    p += 8
    struct.pack_into("<I", buf, p, 2); p += 4   # file_count = 2
    struct.pack_into("<I", buf, p, 0); p += 4

    struct.pack_into("<I", buf, base + 0, dir_off_rel)
    struct.pack_into("<I", buf, base + 4, fd0_off_rel)
    struct.pack_into("<I", buf, base + 8, fd1_off_rel)

    buf[base + dir_off_rel: base + dir_off_rel + len(dirname)] = dirname

    # file0: normal, gueltig
    fp = base + fd0_off_rel
    struct.pack_into("<I", buf, fp, name0_off_rel); fp += 4
    struct.pack_into("<H", buf, fp, 0); fp += 2
    fp += 2
    struct.pack_into("<H", buf, fp, is5.FILE_COMPRESSED); fp += 2
    struct.pack_into("<I", buf, fp, len(valid_content)); fp += 4
    struct.pack_into("<I", buf, fp, len(payload0)); fp += 4
    fp += 0x14
    struct.pack_into("<I", buf, fp, data_offset0); fp += 4
    fp += 0x10

    # file1: FILE_INVALID, komplett mit Datenmuell (auch name_offset!)
    fp = base + fd1_off_rel
    struct.pack_into("<I", buf, fp, 0xFEEDBEEF)  # gigantischer, ungueltiger name_offset
    struct.pack_into("<H", buf, fp + 8, is5.FILE_INVALID)  # flags
    # Rest bleibt Nullen/Muell - irrelevant, da invalid=True

    buf[base + name0_off_rel: base + name0_off_rel + len(filename0)] = filename0
    buf[data_offset0: data_offset0 + len(payload0)] = payload0

    with open(path, "wb") as f:
        f.write(buf)


def run_corrupt_invalid_entry_test():
    """Prueft, dass ein einzelner kaputter (FILE_INVALID mit
    Datenmuell-name_offset) Eintrag NICHT das Laden des gesamten Archivs
    zum Absturz bringt, und dass die uebrigen (gueltigen) Eintraege
    normal nutzbar bleiben."""
    d = "/tmp/corrupttest"
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "corrupt.cab")
    content = b"Das hier ist eine ganz normale, gueltige Datei.\n" * 3

    build_archive_with_corrupt_invalid_entry(path, content)

    header = is5.ISCabHeader(path)  # darf NICHT crashen
    assert header.file_count == 2

    fe_good, fe_bad = header.files
    assert fe_good.name == "gut.txt"
    assert not fe_good.invalid

    assert fe_bad.invalid
    assert fe_bad.name == "<ungueltiger Eintrag>"

    out_path = os.path.join(d, "out_gut.txt")
    is5.extract_file(header, fe_good, out_path)
    with open(out_path, "rb") as f:
        assert f.read() == content

    try:
        is5.extract_file(header, fe_bad, os.path.join(d, "should_not_exist.bin"))
        raise AssertionError("kaputter Eintrag haette abgelehnt werden muessen")
    except is5.ISCabError:
        pass

    print("OK: kaputter FILE_INVALID-Eintrag (Datenmuell-name_offset) stuerzt Laden nicht mehr ab")


def build_selfhosting_multifile_cab(path, contents, vh_mode="zeros", framing="new"):
    """Selbsttragendes Single-Volume-Cab (kein .hdr, kein data2.cab) mit
    mehreren komprimierten Dateien, alle Daten in dieser einen Datei.
    vh_mode steuert den Inhalt des Volume-Header-Bereichs (Bytes 20-60):
      "zeros"    - alles 0 (Header nie befuellt)
      "lastonly" - nur last_file_index = N-1 (wie bei vRally beobachtet)
      "proper"   - sauber befuellt (first=0, last=N-1, Teilgroessen=Gesamt)
    major_version ist 5 (0x3A-Descriptor)."""
    n = len(contents)
    version = (1 << 24) | (5 << 12)
    cab_descriptor_offset = 60
    file_table_offset = 0x30
    base = cab_descriptor_offset + file_table_offset

    arena = _Arena(base)
    arena.reserve((1 + n) * 4)               # file_table: 1 dir + n files
    dir_rel = arena.add(b"\x00") - base
    fd_rel = [arena.reserve(0x3A) - base for _ in range(n)]
    name_rel = [arena.add(("f%d.bin" % i).encode() + b"\x00") - base for i in range(n)]

    payloads = []
    for c in contents:
        if framing == "old":
            # Sync-Flush-Rahmung: Stuecke a 32 KiB, je eigener raw-deflate-Strom,
            # jeweils mit Z_SYNC_FLUSH (endet auf 00 00 FF FF), kein Laengenpraefix
            p = b""
            for i in range(0, len(c), 32768):
                co = zlib.compressobj(9, zlib.DEFLATED, -15)
                p += co.compress(c[i:i + 32768]) + co.flush(zlib.Z_SYNC_FLUSH)
            payloads.append(p)
        else:
            chunk = _compress_chunk(c)
            payloads.append(struct.pack("<H", len(chunk)) + chunk)
    data_off = []
    for p in payloads:
        data_off.append(len(arena.buf))
        arena.add(p)

    buf = arena.buf
    struct.pack_into("<5I", buf, 0, is5.CAB_SIGNATURE, version, 0, cab_descriptor_offset, 0x30)
    struct.pack_into("<%dI" % (1 + n), buf, base, dir_rel, *fd_rel)

    if vh_mode == "lastonly":
        _write_volume_header_v5(buf, 20, first_file_index=0, last_file_index=n - 1,
                                first_size_exp=0, first_size_comp=0,
                                last_size_exp=0, last_size_comp=0)
    elif vh_mode == "proper":
        _write_volume_header_v5(buf, 20, first_file_index=0, last_file_index=n - 1,
                                first_size_exp=len(contents[0]), first_size_comp=len(payloads[0]),
                                last_size_exp=len(contents[-1]), last_size_comp=len(payloads[-1]))
    # "zeros": Bereich bleibt 0

    p = cab_descriptor_offset + 0xC
    struct.pack_into("<I", buf, p, file_table_offset); p += 8
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 0x30); p += 4
    struct.pack_into("<I", buf, p, 1); p += 4      # directory_count
    p += 8
    struct.pack_into("<I", buf, p, n); p += 4      # file_count

    for i in range(n):
        fp = base + fd_rel[i]
        struct.pack_into("<I", buf, fp, name_rel[i]); fp += 4
        fp += 4                                     # directory_index + pad
        struct.pack_into("<H", buf, fp, is5.FILE_COMPRESSED); fp += 2
        struct.pack_into("<I", buf, fp, len(contents[i])); fp += 4
        struct.pack_into("<I", buf, fp, len(payloads[i])); fp += 4
        fp += 0x14
        struct.pack_into("<I", buf, fp, data_off[i])

    with open(path, "wb") as f:
        f.write(buf)


def run_selfhosting_volume_header_test():
    """Selbsttragendes Single-Volume-Cab darf NIE nach einem zweiten
    Volume fragen - egal, ob der Volume-Header-Bereich (Bytes 20-60)
    leer, nur teilweise oder sauber befuellt ist."""
    d = "/tmp/selfhost"
    os.makedirs(d, exist_ok=True)
    contents = [("Datei %d, nur in data1.cab.\n" % i).encode() * (3 + i) for i in range(5)]

    for mode in ("proper", "lastonly", "zeros"):
        path = os.path.join(d, "data1_%s.cab" % mode)
        build_selfhosting_multifile_cab(path, contents, vh_mode=mode)
        header = is5.ISCabHeader(path)
        assert header.file_count == 5 and header.major_version == 5

        asked = []

        def on_missing(e):
            asked.append(e.volume_index)
            return False

        for fe, expected in zip(header.files, contents):
            out = os.path.join(d, "out_%s_%d.bin" % (mode, fe.index))
            is5.extract_file(header, fe, out, on_missing_volume=on_missing)
            with open(out, "rb") as f:
                assert f.read() == expected, (mode, fe.index)
        assert not asked, "vh_mode=%s: unerwartete Nachfrage nach Volume %s" % (mode, asked)
        print("OK selbsttragendes Cab, Volume-Header-Modus %r: 5 Dateien, keine Nachfrage nach Volume 2" % mode)


def run_missing_volume_context_test():
    """Der 'Volume fehlt'-Dialog bekommt einen Diagnosetext (e.context)
    mit Header-Werten, damit ein Screenshot reicht, um die Ursache zu sehen."""
    d = "/tmp/ctxtest"
    os.makedirs(d, exist_ok=True)
    c = [b"A" * 300, bytes((i * 37 + 11) % 251 for i in range(600)), b"C" * 100]
    path = build_split_file_cabs(d, c[0], c[1], c[2], 20)
    os.replace(os.path.join(d, "sptest2.cab"), os.path.join(d, "x_versteckt.cab"))
    header = is5.ISCabHeader(path)
    seen = []

    def cb(e):
        seen.append(e.context)
        return False

    try:
        is5.extract_file(header, header.files[1], os.path.join(d, "o.bin"), on_missing_volume=cb)
        raise AssertionError("haette Volume 2 verlangen muessen")
    except is5.VolumeNotFoundError:
        pass
    assert seen and "last_file_index" in seen[0] and "Datei-Index 1" in seen[0], seen
    print("OK Diagnosetext im Volume-fehlt-Fall: " + seen[0][:70] + "...")


def run_old_framing_test():
    """Archive mit Sync-Flush-Rahmung (kein 2-Byte-Praefix, major_version egal)
    werden automatisch erkannt und korrekt entpackt - inkl. mehrerer Chunks
    je Datei und ohne Nachfrage nach einem zweiten Volume."""
    d = "/tmp/oldframing"
    os.makedirs(d, exist_ok=True)
    rnd = [bytes((i * (k + 3) + (i >> 3) * 7) % 253 for i in range(n)) for k, n in enumerate((900, 28000, 70000, 100000, 33000))]
    path = os.path.join(d, "data1.cab")
    build_selfhosting_multifile_cab(path, rnd, vh_mode="lastonly", framing="old")
    header = is5.ISCabHeader(path)

    asked = []
    for fe, expected in zip(header.files, rnd):
        out = os.path.join(d, "o_%d.bin" % fe.index)
        is5.extract_file(header, fe, out, on_missing_volume=lambda e: asked.append(e) or False)
        with open(out, "rb") as f:
            assert f.read() == expected, "Datei %d" % fe.index
    assert not asked
    print("OK alte Sync-Flush-Rahmung: %d Dateien (bis %d Bytes, mehrere Chunks) automatisch erkannt" % (len(rnd), max(map(len, rnd))))


def run_unknown_framing_diag_test():
    """Passt keine Rahmung, steht eine Hex-Diagnose (Rohbytes) in der Fehlermeldung."""
    d = "/tmp/unkframing"
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "data1.cab")
    junk = [bytes((i * 131 + 17) % 256 for i in range(500)) for _ in range(3)]
    build_selfhosting_multifile_cab(path, junk, vh_mode="lastonly")
    header = is5.ISCabHeader(path)
    fe = header.files[0]
    # Nutzdaten im Archiv durch Muell ersetzen
    with open(path, "r+b") as f:
        f.seek(fe.data_offset)
        f.write(bytes(range(7, 7 + 60)))
    try:
        is5.extract_file(header, fe, os.path.join(d, "o.bin"))
        raise AssertionError("haette scheitern muessen")
    except is5.ISCabError as e:
        assert "Rohbytes @%d" % fe.data_offset in str(e), str(e)
        print("OK unbekannte Rahmung: Fehlermeldung mit Rohbytes-Diagnose")


if __name__ == "__main__":
    run_single_volume_test(obfuscate=False)
    run_single_volume_test(obfuscate=True)
    run_multi_volume_test()
    run_split_extraction_test()
    run_cd_swap_test()
    run_corrupt_invalid_entry_test()
    run_selfhosting_volume_header_test()
    run_missing_volume_context_test()
    run_old_framing_test()
    run_unknown_framing_diag_test()
    print("Alle Selbsttests bestanden.")
