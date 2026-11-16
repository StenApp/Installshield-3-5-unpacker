"""
blast.py - Python-Portierung von blast.c (Mark Adler, 2003-2013,
zlib-Lizenz) - Dekompressor fuer das PKWare Data Compression Library
Format ("explode"), das InstallShield 3 fuer seine .Z-Archive nutzt.

Vereinfachung gegenueber dem Original: Das Original haelt einen
4096-Byte-Ringpuffer (MAXWIN) und prueft Rueckwaerts-Distanzen nur
waehrend des allerersten Fensters (s->first). Da jede gueltige Distanz
per Formatdefinition <= MAXWIN ist, ist "dist > bisher_geschriebene_Bytes"
in jedem Fall die korrekte Fehlerbedingung - hier wird sie durchgehend
geprueft (nicht nur im ersten Fenster), was fuer valide Daten identisches
Verhalten ergibt und fehlerhafte Daten frueher/zuverlaessiger erkennt.
Dadurch kann der komplette Output als einfaches, wachsendes bytearray
gehalten werden statt als Ringpuffer.
"""

MAXBITS = 13
MAXWIN = 4096


class BlastError(Exception):
    pass


class _Huffman:
    __slots__ = ("count", "symbol")

    def __init__(self, count, symbol):
        self.count = count
        self.symbol = symbol


def _construct(rep: bytes):
    """Entspricht construct() in blast.c: rep ist eine kompakte
    Wiederholungs-/Laengenliste (High-Nibble=Anzahl-1, Low-Nibble=Laenge)."""
    length = []
    for b in rep:
        rep_count = (b >> 4) + 1
        code_len = b & 0xF
        length.extend([code_len] * rep_count)

    n_syms = len(length)
    count = [0] * (MAXBITS + 1)
    for ln in length:
        count[ln] += 1
    if count[0] == n_syms:
        return _Huffman(count, [])

    left = 1
    for ln in range(1, MAXBITS + 1):
        left <<= 1
        left -= count[ln]
        if left < 0:
            raise BlastError("blast: Huffman-Tabelle ueberbesetzt (interner Fehler)")

    offs = [0] * (MAXBITS + 2)
    for ln in range(1, MAXBITS):
        offs[ln + 1] = offs[ln] + count[ln]

    symtab = [0] * n_syms
    cursor = offs[:]
    for sym, ln in enumerate(length):
        if ln != 0:
            symtab[cursor[ln]] = sym
            cursor[ln] += 1

    return _Huffman(count, symtab)


def _huffman_encode_table(huff: _Huffman):
    """Nur fuer Tests: liefert {symbol: (code, length)} - der kanonische
    (nicht invertierte) Codewert, MSB zuerst, exakt nach der gleichen
    first/index-Buchfuehrung wie decode() in blast.c."""
    table = {}
    first = 0
    index = 0
    for length in range(1, MAXBITS + 1):
        cnt = huff.count[length]
        for i in range(cnt):
            sym = huff.symbol[index + i]
            table[sym] = (first + i, length)
        index += cnt
        first += cnt
        first <<= 1
    return table


_LITLEN = bytes([
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
    9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
    7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
    8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
    44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
    44, 173,
])
_LENLEN = bytes([2, 35, 36, 53, 38, 23])
_DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])

_BASE = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]

_LITCODE = _construct(_LITLEN)
_LENCODE = _construct(_LENLEN)
_DISTCODE = _construct(_DISTLEN)

END_CODE_LEN = 519  # base[15](264) + extra[15]-Maximalwert(255)


def blast_decompress(data: bytes, max_out=None) -> bytes:
    """Dekomprimiert einen PKWare-DCL/"explode"-komprimierten Bytestring
    (das Format, das InstallShield 3 fuer seine .Z-Archive nutzt).
    max_out: optionale Sicherheitsgrenze (erwartete unkomprimierte
    Groesse aus dem File-Descriptor) - bricht mit BlastError ab, falls
    ueberschritten, statt unbegrenzt Speicher zu allozieren."""
    pos = 0
    n = len(data)
    bitbuf = 0
    bitcnt = 0

    def bits(need):
        nonlocal pos, bitbuf, bitcnt
        val = bitbuf
        while bitcnt < need:
            if pos >= n:
                raise BlastError("blast: unerwartetes Ende der komprimierten Daten")
            val |= data[pos] << bitcnt
            pos += 1
            bitcnt += 8
        bitbuf = val >> need
        bitcnt -= need
        return val & ((1 << need) - 1)

    def decode(huff: _Huffman):
        code = 0
        first = 0
        index = 0
        for length in range(1, MAXBITS + 1):
            code |= (bits(1) ^ 1)
            cnt = huff.count[length]
            if code < first + cnt:
                return huff.symbol[index + (code - first)]
            index += cnt
            first += cnt
            first <<= 1
            code <<= 1
        raise BlastError("blast: ungueltiger oder unvollstaendiger Huffman-Code")

    out = bytearray()

    lit = bits(8)
    if lit > 1:
        raise BlastError("blast: ungueltiges Literal-Flag (%d) - falsches Format?" % lit)
    dict_bits = bits(8)
    if dict_bits < 4 or dict_bits > 6:
        raise BlastError("blast: ungueltige Dictionary-Groesse (%d) - falsches Format?" % dict_bits)

    while True:
        if bits(1):
            symbol = decode(_LENCODE)
            length = _BASE[symbol] + bits(_EXTRA[symbol])
            if length == END_CODE_LEN:
                break

            dsym = 2 if length == 2 else dict_bits
            dist = (decode(_DISTCODE) << dsym) + bits(dsym) + 1

            if dist > len(out):
                raise BlastError(
                    "blast: Distanz zu weit zurueck (dist=%d, bisher %d Bytes)"
                    % (dist, len(out))
                )
            start = len(out) - dist
            for i in range(length):
                out.append(out[start + i])
        else:
            symbol = decode(_LITCODE) if lit else bits(8)
            out.append(symbol)

        if max_out is not None and len(out) > max_out:
            raise BlastError(
                "blast: Ausgabe (%d Bytes) uebersteigt erwartete Groesse (%d) - "
                "vermutlich beschaedigte oder falsch interpretierte Daten"
                % (len(out), max_out)
            )

    return bytes(out)
