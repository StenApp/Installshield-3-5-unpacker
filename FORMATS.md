# InstallShield-Archivformate: IS3 und IS5.x

Referenzdokumentation zu den Formaten, die `is3.py` und `is5.py`
implementieren. Stand: gegen mehrere unabhängige Quellen abgeglichen
und teilweise gegen echte Archive verifiziert (siehe „Verifikationsstatus"
am Ende jedes Abschnitts).

---

## 1. InstallShield 3 (`.Z`-Archive)

### 1.1 Erkennung

- Signatur (8 Bytes, Offset 0): `13 5D 65 8C 3A 01 02 00`
- Dateiendung meist `.Z`, Split-Teile `.1`, `.2`, ... (bare Nummer, siehe 1.5)
- Erzeugt von `i3comp.exe` ("InstallShield File Compressor", Stirling
  Technologies, 1990–1995)

### 1.2 Archiv-Header (255 Bytes, `ICOMP_CB_HEADER`)

Fixe Größe, auch wenn nicht alle Bytes genutzt werden.

| Offset | Typ | Feld | Bedeutung |
|---|---|---|---|
| 0x00 | u8[8] | signature | `13 5D 65 8C 3A 01 02 00` |
| 0x0A | u16 | flags | Bit 0x1 = Archiv ist gesplittet |
| 0x0C | u16 | num_files | Anzahl Dateieinträge |
| 0x0E | u32 | datetime | MS-DOS-Datum/Zeit |
| 0x12 | u32 | archive_size | Größe dieser Archivdatei |
| 0x16 | u32 | total_size | Summe aller unkomprimierten Dateigrößen |
| 0x1E | u8 | num_split | Gesamtzahl Archivteile (nur wenn gesplittet) |
| 0x1F | u8 | cur_seq | Teilnummer *dieser* Datei (1-basiert) |
| 0x20 | u8 | check_byte | `total_compacted_size % 253` |
| 0x21 | u32 | end_integral_data | Grenzmarke (Split, siehe 1.5) |
| 0x25 | u32 | start_integral_data | Grenzmarke (Split, siehe 1.5) |
| 0x29 | u32 | dir_offset | Offset des Verzeichnis-Eintrags-Blocks |
| 0x31 | u16 | num_dirs | Anzahl Verzeichniseinträge |
| 0x33 | u32 | file_offset | Offset des Datei-Eintrags-Blocks |

Felder zwischen 0x00–0x33, die hier fehlen, sind Padding/unbenutzt.

### 1.3 Verzeichnis-Eintrag (variable Länge, min. 6 Bytes)

| Offset | Typ | Feld |
|---|---|---|
| +0x00 | u16 | num_files (Dateien in diesem Verzeichnis) |
| +0x02 | u16 | entry_size (Gesamtlänge dieses Eintrags) |
| +0x04 | u8 | name_length |
| +0x05 | u8 | unbenutzt |
| +0x06 | char[name_length] | Name (**nicht** null-terminiert – Länge kommt aus name_length) |

Nächster Eintrag folgt direkt bei `offset + entry_size`.

### 1.4 Datei-Eintrag (variable Länge, min. 0x1E=30 Bytes + Name)

| Offset | Typ | Feld |
|---|---|---|
| +0x00 | u8 | seq_last (Teilnummer, in dem die Datei *endet*) |
| +0x01 | u16 | directory (Index in die Verzeichnisliste) |
| +0x03 | u32 | size (unkomprimiert) |
| +0x07 | u32 | comp_size (komprimiert, **Summe über alle Teile** bei Split) |
| +0x0B | u32 | comp_offset (Offset der Daten *im ersten beteiligten Teil*) |
| +0x0F | u32 | datetime |
| +0x13 | u8 | attributes |
| +0x14 | u8[3] | unbenutzt |
| +0x17 | u16 | hdr_size (Gesamtlänge dieses Eintrags) |
| +0x19 | u16 | **flags** (siehe unten – volles 16-Bit-Feld!) |
| +0x1B | u8 | unbenutzt |
| +0x1C | u8 | seq_first (Teilnummer, in dem die Datei *beginnt*) |
| +0x1D | u8 | name_length |
| +0x1E | char[name_length] | Name (nicht null-terminiert) |

**Besonderheit:** `isdecomp.h` (eine der beiden Referenzquellen)
dokumentiert Offset 0x19 als separates `unknown2`-Byte und 0x1A als
eigenes `partial`-Byte (Bit 0 = Split). Das ist bit-identisch mit der
Interpretation als **ein** 16-Bit-Feld ab 0x19 – die zweite Quelle
(`idecomp.py`) liest es korrekt als volles Feld und deckt damit
zusätzliche Bits auf:

| Bit | Wert | Bedeutung |
|---|---|---|
| 0x100 | 256 | Datei über mehrere Archivteile gesplittet |
| 0x040 | 64 | Hat Versionsinfo (nicht immer gesetzt) |
| 0x020 | 32 | **Ungültig** – von `icomp.exe` beim Entfernen einer Datei genutzt, Eintrag bleibt als Leiche stehen |
| 0x010 | 16 | **Gespeichert, nicht komprimiert** – Rohdaten direkt im Archiv, kein `blast()` nötig |

Nach dem Namen folgen bei manchen Archiven noch 12 weitere Bytes
(vermutlich `versionMS`/`versionLS`/unbenutzt) – werden beim Parsen
ignoriert, da `hdr_size` die tatsächliche Eintragslänge vorgibt.

### 1.5 Split-Archive

Namensschema: **`<Basisname ohne Endung>.<Teilnummer>`**, z.B. `SETUP.Z`
→ Fortsetzungen `SETUP.2`, `SETUP.3`, ... (bare Zahl, **keine** `.Z`-Endung
auf den Folgeteilen). Jeder Teil trägt einen vollständigen 255-Byte-Header
mit eigenem `cur_seq`.

Für eine über mehrere Teile gesplittete Datei (`seq_first` ≠ `seq_last`):

- **Erster beteiligter Teil:** Daten beginnen bei `comp_offset`, enden bei
  `dir_offset` dieses Teils (bzw. `start_integral_data`, falls dies auch
  der letzte Teil ist).
- **Mittlere Teile:** Daten beginnen bei Byte 255 (direkt nach dem
  Header), enden bei `dir_offset` dieses Teils.
- **Letzter beteiligter Teil:** Daten beginnen bei Byte 255, enden bei
  `start_integral_data` dieses Teils (= Grenze, ab der wieder vollständige,
  nicht gesplittete Dateien in diesem Teil folgen).

Die Rohbytes aller beteiligten Teile werden aneinandergehängt und
**einmal am Stück** durch `blast()` gejagt (PKWare-Explode ist ein
durchgehender Bitstream, kein Chunk-Format wie bei IS5.x zlib).

`icomp.exe` extrahiert standardmäßig nur Dateien, die im *aktuell
geladenen* Teil vollständig verfügbar sind; für die korrekte
Gesamtliste sollte immer **Teil 1** geladen werden.

### 1.6 Kompression: PKWare DCL "Explode"

- Implementiert in `blast.py`, portiert aus Mark Adlers `blast.c`
  (zlib-Contrib, öffentliche Domain / zlib-Lizenz).
- Bitstream-Header: 1 Byte `lit` (0/1 = Literale unkodiert/Huffman-kodiert),
  1 Byte `dict` (4/5/6 = log2(Fenstergröße)−6).
- Danach abwechselnd Literale oder Länge/Distanz-Paare (LZ77-artig,
  Fenster max. 4096 Bytes), je ein Flag-Bit davor.
- Canonical-Huffman-Codes sind **bitinvertiert** im Stream gespeichert.
- Referenzvektor (aus `blast.c` selbst, unabhängig auch in `idecomp.py`
  verifiziert): `00 04 82 24 25 8F 80 7F` → `"AIAIAIAIAIAIA"`.

### 1.7 Verifikationsstatus (IS3)

| Bereich | Status |
|---|---|
| Header/Verzeichnis/Datei-Parsing | ✅ echtes Archiv (33 Dateien, LithTech-Tools) |
| `blast()`-Kompressionskern | ✅ offizieller Referenzvektor + unabhängige Zweitimplementierung stimmen überein |
| `stored`-Flag (unkomprimiert) | ⚠️ nur synthetisch getestet |
| `invalid`-Flag | ⚠️ nur synthetisch getestet |
| Split-Archive | ⚠️ nur synthetisch getestet, kein echtes Mehrteil-Archiv verfügbar |
| Sub-Versionen (falls es sie gibt) | ❓ keine Hinweise auf mehrere strukturell unterschiedliche IS3-Versionen gefunden |

---

## 2. InstallShield 5.0 / 5.1 / 5.5 (`.hdr`/`.cab`)

### 2.1 Erkennung

- Signatur (4 Bytes, little-endian): `ISc(` (Hex `49 53 63 28`)
- `data1.hdr` trägt Header + Verzeichnis-/Dateiliste (Katalog).
  `data1.cab`, `data2.cab`, ... tragen die eigentlichen Nutzdaten
  ("Volumes"). Existiert kein separates `.hdr`, steckt der Katalog in
  `data1.cab` selbst (Single-File-Fall).
- Drei real existierende Punktversionen bestätigt: 5.0, 5.1, 5.5
  (1997–1998). Zwei unterschiedliche `version`-Feld-Stempel real
  beobachtet: `0x01000004` (→ `major_version=0`, vRally/Donald-Duck) und
  `0x01005201` (→ `major_version=5`, Quake 3). **Wichtiger Befund:**
  `major_version` (0 vs. 5, das MD5-Feld im File-Descriptor) ist **keine
  InstallShield-Punktversion-Angabe**, sondern eine reine Cab-Struktur-
  Einstellung, unabhängig von der Engine-Version - bestätigt dadurch,
  dass Quake 3 (`major_version=5`) und vRally (`major_version=0`) einen
  **byte-identischen** `_INST32I.EX_`-Bootstrap-Stub mitbringen (gleicher
  MD5-Hash, gleiche eingebettete Komponenten `ZDataI51.dll`/
  `_WUTL951.DLL` mit "51"-Versionsmarkierung) - also nachweislich
  dieselbe InstallShield-5.1-Engine, trotz unterschiedlichem
  `major_version`-Wert in der jeweiligen `.hdr`-Datei.

### 2.2 Common Header (20 Bytes, immer am Dateianfang)

| Offset | Typ | Feld |
|---|---|---|
| 0x00 | u32 | signature (`ISc(`) |
| 0x04 | u32 | version (codiert `major_version`, siehe unten) |
| 0x08 | u32 | volume_info |
| 0x0C | u32 | cab_descriptor_offset |
| 0x10 | u32 | cab_descriptor_size |

**`major_version`-Herleitung** aus `version`:
```
if (version >> 24) == 1:      major = (version >> 12) & 0xF
elif (version >> 24) in (2,4): major = (version & 0xFFFF) // 100  (oder 0)
else:                          major = 0
```
Unterstützt werden `major_version` 0 und 5 (identisches Layout, siehe
2.4). 6+ hat ein komplett anderes File-Descriptor-Layout und wird
**nicht** unterstützt.

### 2.3 Volume-Header (40 Bytes, Offset 20–60 – **nur** in reinen
Datenvolumes ohne eigenen Cab-Descriptor, z.B. `data2.cab`)

| Offset (relativ) | Typ | Feld |
|---|---|---|
| +0x00 | u32 | data_offset |
| +0x04 | u32 | unbenutzt |
| +0x08 | u32 | first_file_index |
| +0x0C | u32 | last_file_index |
| +0x10 | u32 | first_file_offset |
| +0x14 | u32 | first_file_size_expanded |
| +0x18 | u32 | first_file_size_compressed |
| +0x1C | u32 | last_file_offset (Sentinel `0` → als `INT32_MAX` behandeln) |
| +0x20 | u32 | last_file_size_expanded |
| +0x24 | u32 | last_file_size_compressed |

**Wichtig:** Bei einer `.hdr`-Datei (oder einer `data1.cab`, die *auch*
den Header trägt) liegt an dieser Stelle **kein** Volume-Header, sondern
der Anfang des Cab-Descriptors – die Werte sehen dann unplausibel aus
und werden ignoriert.

### 2.4 Cab-Descriptor (variable Position, `cab_descriptor_offset`)

Nur relevante, tatsächlich genutzte Felder:

| Offset (relativ zu cab_descriptor_offset) | Typ | Feld |
|---|---|---|
| +0x0C | u32 | file_table_offset |
| +0x14 | u32 | file_table_size |
| +0x18 | u32 | file_table_size2 |
| +0x1C | u32 | directory_count |
| +0x28 | u32 | file_count |
| +0x2C | u32 | file_table_offset2 |

Danach (nicht genutzt, aber vorhanden): bis zu 71 File-Group-Offsets,
71 Component-Offsets.

**File-Table** ab `cab_descriptor_offset + file_table_offset`:
`directory_count + file_count` aufeinanderfolgende `u32`-Offsets
(relativ zur File-Table-Basis) – erst die Verzeichnisnamen, dann die
Datei-Deskriptoren.

- **Verzeichnisname:** null-terminierter String am jeweiligen Offset.
- **Datei-Deskriptor:** siehe 2.5.

### 2.5 Datei-Deskriptor

Layout identisch für `major_version` 0 und 5, **außer** MD5-Feld:

| Offset (relativ) | Typ | Feld |
|---|---|---|
| +0x00 | u32 | name_offset (relativ zur File-Table-Basis) |
| +0x04 | u16 | directory_index |
| +0x06 | – | Padding (2 Bytes) |
| +0x08 | u16 | **flags** |
| +0x0A | u32 | expanded_size |
| +0x0E | u32 | compressed_size |
| +0x12 | – | Padding (0x14=20 Bytes) |
| +0x26 | u32 | data_offset |
| +0x2A | u8[16] | MD5 (**nur bei major_version==5**, entfällt bei 0) |

Gesamtlänge: `0x3A` (58 Bytes) bei major_version 5, `0x2A` (42 Bytes)
bei major_version 0.

**Flags-Bits:**

| Bit | Wert | Bedeutung |
|---|---|---|
| 0x1 | FILE_SPLIT | Über Volume-Grenze gesplittet (siehe 2.7) |
| 0x2 | FILE_OBFUSCATED | Bytes zusätzlich verschleiert (siehe 2.8) |
| 0x4 | FILE_COMPRESSED | zlib-komprimiert (fehlt = unkomprimiert/extern, siehe 2.9) |
| 0x8 | FILE_INVALID | Gelöschter/Platzhalter-Eintrag |

### 2.6 Kompression: zlib raw deflate, Chunk-Format

Kein einzelner durchgehender Deflate-Stream, sondern in Chunks:

```
solange bytes_left (== compressed_size) > 0:
    chunk_size := u16 (2 Bytes, little-endian)
    chunk      := chunk_size Bytes
    output    += raw_inflate(chunk, wbits=-15)   # je EIGENER Decompressor pro Chunk
    bytes_left -= 2 + chunk_size
```

Jeder Chunk ist ein eigenständiger, in sich abgeschlossener
Deflate-Block (sync-flush-Grenze) – deshalb pro Chunk ein frischer
`zlib.decompressobj(-15)`.

Ein `chunk_size == 0` deutet darauf hin, dass die 2-Byte-Längenpräfix-
Rahmung hier nicht passt (wird erkannt und abgelehnt statt falsch
interpretiert). **Korrektur einer früheren Fehlannahme:** Das ist
*nicht* zuverlässig an `major_version < 5` gekoppelt und *nicht*
dasselbe wie IS3s PKWare-Explode. Im `unshield`-Quellcode gibt es dafür
eine separate Funktion `unshield_file_save_old()` (nur über das manuelle
`-O`-Kommandozeilenflag erreichbar, als Fallback bei fehlgeschlagener
"neuer" Dekompression) – sie liest ebenfalls zlib/deflate, sucht Chunk-
Grenzen aber über den Sync-Flush-Marker `00 00 FF FF` im Bytestrom statt
über eine explizite Längenangabe. **Seit der MRS-Beobachtung in `is5.py`
als automatischer Fallback implementiert:** Passt die Längenpräfix-Rahmung
nicht (`chunk_size == 0`, `chunk_size` größer als der Rest von
`compressed_size`, zlib-Fehler oder falsche Gesamtgröße), liest `is5.py` die
komprimierten Bytes am Stück und teilt sie an `00 00 FF FF` in Chunks. Ein
Marker, dessen Folgebyte Bit 0 gesetzt hat, liegt mitten in einem Chunk und
wird übersprungen (wie im Original). Jeder Chunk wird mit frischem
`zlib.decompressobj(-15)` entpackt. Passt keine der beiden Rahmungen, nennt
die Fehlermeldung die ersten 16 und letzten 8 Rohbytes der Datei.

### 2.7 Multi-Volume und Split-Dateien

- Volumes heißen `data1.cab`, `data2.cab`, ... im selben Ordner wie
  die `.hdr` (case-insensitive gesucht).
- **Auflösung des Startvolumes** einer Datei: ab Volume 1 aufsteigend
  prüfen, ob `entry.index <= volume.last_file_index`; wenn nicht,
  nächstes Volume probieren.
- **Unbefüllter Volume-Header (Vermutung, nur synthetisch getestet):**
  Ist der Bereich bei Byte 20–60 einer selbsttragenden `data1.cab` komplett
  0 (first=last=0, alle Offsets/Größen 0, `file_count > 1`), ist das kein
  echter Header – `is5.py` nimmt dann `last_file_index = file_count-1`
  an, sonst würde schon die zweite Datei ein nicht existierendes `data2.cab`
  verlangen. Zusätzlich gilt eine Datei nur dann als gesplittet, wenn das
  Teilstück real ist (Größe > 0, Offset gesetzt) und die Datei laut
  `data_offset + compressed_size` nicht komplett ins Volume passt.
- **Split-Erkennung** (nur bei `major_version == 5`, **nicht** bei 0 –
  im Original explizit so beschränkt):
  - Datei ist "letzte in diesem Volume" (`index == last_file_index`,
    `index < file_count-1`) UND `last_file_size_compressed !=
    compressed_size` → Rest liegt im nächsten Volume,
    `last_file_offset`/`last_file_size_*` verwenden.
  - Datei ist "erste in diesem Volume" (`index == first_file_index`,
    `index > 0`) UND `first_file_size_compressed != compressed_size`
    → Anfang lag im vorherigen Volume, `first_file_offset`/
    `first_file_size_*` verwenden.
  - Beide Bedingungen greifen **nicht** für die allererste bzw.
    allerletzte Datei im gesamten Archiv (Guard `index > 0` bzw.
    `index < file_count-1`).
- Eine Datei kann über **mehr als zwei** Volumes verteilt sein (Code
  ist als Schleife gebaut), aber nur der Zwei-Volume-Fall wurde bisher
  getestet.
- `data_offset` ist **immer relativ zur Datei, in der er tatsächlich
  gefunden wird** – beim Wechsel zwischen Volumes ändert sich die
  Referenz automatisch mit.

### 2.8 Obfuskierung

Wenn `FILE_OBFUSCATED` gesetzt ist, werden **alle** rohen Bytes (die
2-Byte-Chunk-Größen *und* die Chunk-Nutzdaten, in Leseeihenfolge) vor
der Interpretation entschlüsselt:

```
seed := 0  (pro Datei-Extraktion neu, läuft über ALLE gelesenen Bytes)
für jedes Byte b:
    b := (b XOR 0xD5)
    b := ror8(b, 2)                    # 8-bit Rotate-Right um 2
    b := (b - (seed % 0x47)) & 0xFF
    seed += 1
```

Betrifft **auch** die Volume-Grenze: der Seed läuft nahtlos weiter,
unabhängig davon, ob gerade Volume 1 oder Volume 2 gelesen wird.

### 2.9 Nicht eingebettete ("externe") Dateien

Eine reale Besonderheit, die in keiner der Referenzquellen explizit
benannt war, aber an echten Archiven beobachtet wurde. Ganze
Dateigruppen können im InstallShield-Projekt auf "nicht komprimieren"
gestellt sein – die Datei ist dann gar nicht im Cab eingebettet,
sondern liegt unverändert im Quellverzeichnis neben dem Setup
(identische Ordnerstruktur wie im Katalog angegeben) und wird vom
Installer per einfacher Dateikopie installiert. **Zwei unterschiedliche
Kodierungen dafür real beobachtet**, je nach Archiv/Version:

**Variante A** (Quake 3, `major_version=5`):
- `flags == 0` (kein FILE_COMPRESSED, kein FILE_INVALID)
- `data_offset == 0`
- Erkennbar z.B. an einer winzigen `data1.cab` (wenige hundert Bytes)
  trotz hunderter Katalogeinträge mit mehreren hundert MB Gesamtgröße.

**Variante B** (vRally, `major_version=0` – laut Bootstrap-Stub
`_INST32I.EX_` dieselbe InstallShield-5.1-Engine wie Quake 3, das
`major_version=5` nutzt; siehe Befund in 2.1):
- `FILE_COMPRESSED` bleibt **gesetzt** (`flags=0x4`)
- `expanded_size == compressed_size` (identischer Platzhalterwert,
  keine echte Kompressionsangabe)
- `data_offset` zeigt exakt auf das Ende der (selbsttragenden)
  Cab-Datei, bei **jedem einzelnen** Eintrag identisch
- Erkennbar daran, dass der Katalog (Dateideskriptoren + Namen)
  praktisch die komplette Cab-Datei ausfüllt – für echte Nutzdaten ist
  kein Platz mehr

Ohne Variante B zu erkennen, schlägt die Extraktion mit einer
irreführenden "Unerwartetes Dateiende"-Meldung fehl, statt den
eigentlichen Grund zu nennen – beide Varianten werden daher über
`FileEntry.is_external(header)` erkannt (generalisiert gegenüber der
reinen `not_embedded`-Property, die nur Variante A abdeckt).

### 2.10 Ungültige Einträge

`FILE_INVALID` (Bit 0x8) markiert einen gelöschten/Platzhalter-Eintrag
– die Datei wurde im Original-Projekt entfernt, der Slot in der
File-Table bleibt aber bestehen (kein Nachrücken der Indizes). Name
kann Datenmüll enthalten, `expanded_size`/`compressed_size` meist 0.

### 2.11 Verifikationsstatus (IS5.x)

| Bereich | Status |
|---|---|
| Header/Verzeichnis/Datei-Parsing | ✅ echtes Archiv (549 Dateien, Quake 3) |
| zlib-Chunk-Dekompression | ✅ echte Extraktion bestätigt |
| Multi-Volume-Auflösung | ✅ echte Daten (`data1.cab`/`data2.cab`, 179 Dateien) |
| Split-Datei über Volume-Grenze | ✅ byte-genau gegen echte Volume-Header-Felder verifiziert (`WORLDS.REZ`) |
| Ungültige Einträge | ✅ echtes Archiv |
| Nicht eingebettete/externe Dateien | ✅ echtes Archiv (Quake 3, `data1.cab` = 469 Bytes) |
| `major_version 0` | ✅ echtes Archiv (vRally, 718 Dateien, 40 Verzeichnisse, `version=0x01000004`) – laut Nutzer ein IS5.1-Titel |
| Obfuskierung | ⚠️ nur synthetisch getestet – in **keinem** der gesehenen echten Archive (571 Dateien über 3 Header) überhaupt verwendet |
| Datei über 3+ Volumes gesplittet | ⚠️ Code unterstützt es (Schleife), nur 2-Volume-Fall getestet |
| IS6+ | ❌ nicht unterstützt (anderes Layout) |
| Alternatives Chunk-Format (`unshield_file_save_old`, Sync-Flush-Marker statt Längenpräfix) | ⚠️ implementiert (Auto-Fallback), nur synthetisch getestet; Vermutung: tritt bei MRS (`major_version=0`, 656 Dateien) auf, noch nicht an echten Bytes bestätigt; **nicht** dasselbe wie IS3 |

---

## 3. Quellen

- [`unshield`](https://github.com/twogood/unshield) (MIT) – primäre
  Quelle für das IS5.x-Layout, insbesondere `lib/file.c` und
  `lib/libunshield.c`.
- [`isdecomp`](https://github.com/putara/isdecomp) (WTFPL) – primäre
  Quelle für das IS3-Header-Layout (`isdecomp.h`), inkl. `blast.c`
  (Mark Adler, zlib-Lizenz) als Kompressions-Referenz.
- [`idecomp`](https://github.com/lephilousophe/idecomp) (GPLv3) –
  unabhängige Python-Implementierung, löst mehrere „unknown"-Felder
  aus `isdecomp.h` auf (insbesondere das volle Flags-Feld und die
  Split-Archiv-Mechanik) und bestätigt die IS3-Header-Offsets, die
  `is3.py` tatsächlich nutzt.
- [archiveteam.org – InstallShield Z](http://fileformats.archiveteam.org/wiki/InstallShield_Z) –
  Signatur-Bestätigung, Verweis auf o.g. Quellen.
- Diagnose-Runs mit `is5_diag.bt` (010 Editor Binary Template) gegen
  echte `data1.hdr`/`data1.cab`/`data2.cab` sowie Konsolen-Output von
  `isviewer_gui.py` gegen echte Archive.
