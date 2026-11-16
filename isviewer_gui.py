#!/usr/bin/env python3
"""
isviewer_gui.py - GUI zum Ansehen und selektiven Entpacken von
InstallShield-Archiven:
  - IS5.0/5.1/5.5 Cabinet-Archive (.hdr/.cab) ueber is5.py
  - IS3-Archive (.Z) ueber is3.py

Das Format wird beim Oeffnen automatisch anhand der Signatur der
Datei erkannt (ISc( fuer IS5.x, 13 5D 65 8C 3A 01 02 00 fuer IS3).

Reines Python (Tkinter, nur Standardbibliothek). Kein externes
Binary/OCX noetig.

Start: python isviewer_gui.py
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import is5
import is3


CHECK_ON = "\u2611"   # ☑
CHECK_OFF = "\u2610"  # ☐


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f TB" % n


def detect_format(path):
    """Liest die ersten Bytes und gibt 'is5', 'is3' oder None zurueck."""
    with open(path, "rb") as f:
        head = f.read(8)
    if len(head) >= 4 and head[:4] == b"ISc(":
        return "is5"
    if head[:8] == is3.SIGNATURE:
        return "is3"
    return None


def _find_case_insensitive(folder, filename):
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return None
    for entry in entries:
        if entry.lower() == filename.lower():
            return os.path.join(folder, entry)
    return None


def prefer_sibling_hdr(path):
    """Wenn eine .cab-Datei geoeffnet wird und im selben Ordner eine
    gleichnamige .hdr liegt (z.B. data1.cab -> data1.hdr), wird die
    .hdr bevorzugt - sie traegt den vollstaendigen Katalog, waehrend
    die .cab manchmal nur ein Datenvolume oder sogar ein fast leerer
    Stub ist (gesehen: 3675 Bytes, 0 Dateien, echter Katalog steckte
    im separaten .hdr). Gibt (tatsaechlicher_pfad, wurde_ersetzt) zurueck."""
    folder, base = os.path.split(path)
    stem, ext = os.path.splitext(base)
    if ext.lower() != ".cab":
        return path, False
    candidate = _find_case_insensitive(folder, stem + ".hdr")
    if candidate and os.path.abspath(candidate) != os.path.abspath(path):
        return candidate, True
    return path, False


class ISCabGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("InstallShield-Viewer (IS3 / IS5.x)")
        self.root.geometry("900x780")

        self.header = None
        self.backend = None  # "is5" oder "is3"
        self.checked = {}  # iid -> bool
        self._invalid_iids = set()
        self._cancel_extraction = False  # True, wenn der Nutzer in einem Dialog 'Abbrechen' gewaehlt hat

        self._build_widgets()

    def _build_widgets(self):
        top = ttk.Frame(self.root, padding=6)
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(top, text="Datei öffnen...", command=self.on_open).pack(side=tk.LEFT)
        self.path_label = ttk.Label(top, text="Keine Datei geladen.")
        self.path_label.pack(side=tk.LEFT, padx=10)

        mid_btns = ttk.Frame(self.root, padding=(6, 0))
        mid_btns.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(mid_btns, text="Alle auswählen", command=self.select_all).pack(side=tk.LEFT)
        ttk.Button(mid_btns, text="Auswahl aufheben", command=self.select_none).pack(side=tk.LEFT, padx=4)
        ttk.Button(mid_btns, text="Extrahieren...", command=self.on_extract).pack(side=tk.LEFT, padx=20)

        columns = ("check", "name", "dir", "size", "csize", "flags")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("check", text="")
        self.tree.heading("name", text="Dateiname")
        self.tree.heading("dir", text="Verzeichnis")
        self.tree.heading("size", text="Größe")
        self.tree.heading("csize", text="Komprimiert")
        self.tree.heading("flags", text="Flags")

        self.tree.column("check", width=30, anchor="center", stretch=False)
        self.tree.column("name", width=260)
        self.tree.column("dir", width=200)
        self.tree.column("size", width=90, anchor="e")
        self.tree.column("csize", width=90, anchor="e")
        self.tree.column("flags", width=110)

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        # Statuszeile ZUERST packen (side=BOTTOM), damit sie die volle
        # Fensterbreite beansprucht, bevor Tabelle/Scrollbar den Rest der
        # Flaeche (side=LEFT) fuer sich beanspruchen. Andersrum wuerde die
        # Statuszeile nur in der schmalen Luecke rechts neben der
        # Scrollbar landen, nicht ueber die volle Breite unten.
        self.status = ttk.Label(self.root, text="Bereit.", anchor="w", padding=4)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=6)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=6)

        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<space>", self.on_tree_space)

    # -- Datei laden -----------------------------------------------------

    def on_open(self):
        path = filedialog.askopenfilename(
            title="InstallShield-Archiv öffnen",
            filetypes=[
                ("InstallShield (HDR/CAB/Z/Teil-Dateien)",
                 "*.hdr *.HDR *.cab *.CAB *.z *.Z "
                 "*.1 *.2 *.3 *.4 *.5 *.6 *.7 *.8 *.9"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if not path:
            return

        fmt = detect_format(path)
        if fmt is None:
            messagebox.showerror(
                "Unbekanntes Format",
                "Weder eine 'ISc('-Signatur (IS5.x) noch eine IS3-Signatur "
                "gefunden. Ist das wirklich ein InstallShield-Archiv?",
            )
            return

        redirected = False
        if fmt == "is5":
            path, redirected = prefer_sibling_hdr(path)

        try:
            if fmt == "is5":
                header = is5.ISCabHeader(path)
            else:
                header = is3.IS3Header(path)
        except (is5.ISCabError, is3.IS3Error) as e:
            messagebox.showerror("Fehler beim Laden", str(e))
            return
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Unerwarteter Fehler", "%s: %s" % (type(e).__name__, e))
            return

        self.header = header
        self.backend = fmt
        label = os.path.basename(path)
        if redirected:
            label += "  (statt .cab: daneben liegendes .hdr geladen)"
        self.path_label.config(text="%s  [%s]" % (label, fmt.upper()))
        self.populate_tree()

        if fmt == "is5":
            self.status.config(
                text="Geladen (IS5.x): %d Dateien, %d Verzeichnisse, Major-Version %d"
                % (header.file_count, header.directory_count, header.major_version)
            )
        else:
            split_info = (" - Split-Archiv, Teil %d/%d" % (header.cur_seq, header.num_split)) if header.split else ""
            self.status.config(
                text="Geladen (IS3): %d Dateien, %d Verzeichnisse%s"
                % (header.num_files, header.num_dirs, split_info)
            )

        hint = self._empty_or_external_hint(header, fmt, path, redirected)
        if hint:
            messagebox.showinfo("Hinweis", hint)

    def _empty_or_external_hint(self, header, fmt, path, redirected):
        """Liefert einen erklaerenden Hinweistext, wenn der geladene
        Katalog leer ist oder ausschliesslich nicht eingebettete
        (externe) Dateien enthaelt - beides sieht sonst wie ein Fehler
        oder eine leere/kaputte Datei aus, ist aber normales Verhalten
        bei manchen Installern (z.B. wenn die echten Dateien unverpackt
        neben dem Setup liegen und nur kopiert statt entpackt werden)."""
        folder = os.path.dirname(path)

        if fmt == "is5":
            if header.file_count == 0:
                extra = "" if redirected else (
                    "\n\nEs wurde auch keine passende .hdr-Datei neben der .cab gefunden - "
                    "falls du eine erwartest, pruef den Dateinamen."
                )
                return (
                    "Dieser Katalog enthält keine Dateien (file_count=0).\n\n"
                    "Das deutet darauf hin, dass diese .cab nur ein Stub der "
                    "Setup-Engine ist und die eigentlichen Programm-/Spieldateien "
                    "gar nicht über dieses Cab installiert werden. Schau nach, ob "
                    "im Installationsverzeichnis (z.B. eine Ordnerebene über '%s') "
                    "weitere Ordner mit unverpackten Dateien liegen, die einfach "
                    "kopiert statt entpackt werden.%s" % (os.path.basename(folder), extra)
                )
            if header.file_count > 0 and all(fe.is_external(header) for fe in header.files):
                return (
                    "Alle %d Dateien in diesem Katalog sind nicht im Cab "
                    "eingebettet (kein Kompressions-Flag, kein Datenoffset) - "
                    "sie liegen unverändert im Quellverzeichnis und werden per "
                    "Kopie statt Cab-Extraktion installiert. Du kannst sie trotzdem "
                    "über 'Extrahieren...' holen (Tool kopiert sie automatisch aus "
                    "dem Quellordner), falls sie dort tatsächlich vorhanden sind."
                    % header.file_count
                )
        else:
            if header.num_files == 0:
                return (
                    "Dieses IS3-Archiv enthält keine Dateien (num_files=0). "
                    "Schau nach, ob die eigentlichen Dateien unverpackt in einem "
                    "Geschwisterordner liegen statt in diesem Archiv."
                )

        return None

    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.checked.clear()
        self._invalid_iids = set()

        self.tree.tag_configure("invalid", foreground="#999999")
        self.tree.tag_configure("external", foreground="#a05a00")

        for fe in self.header.files:
            flag_names = []
            is_unselectable = False
            tag = None
            if self.backend == "is5":
                if fe.compressed:
                    flag_names.append("komprimiert")
                if fe.obfuscated:
                    flag_names.append("obfuskiert")
                if fe.invalid:
                    flag_names.append("UNGÜLTIG")
                    is_unselectable = True
                    tag = "invalid"
                if fe.is_external(self.header):
                    flag_names.append("EXTERN (wird kopiert)")
                    tag = "external"
                if fe.flags & is5.FILE_SPLIT:
                    flag_names.append("SPLIT")
                if not flag_names:
                    # Weder komprimiert noch extern/ungueltig/split: die
                    # Datei ist ganz normal eingebettet, nur unkomprimiert
                    # abgelegt (z.B. der Haupt-Launcher, waehrend grosse
                    # Ressourcen komprimiert werden) - eigenes Label statt
                    # einer leeren Spalte, die wie ein Darstellungsfehler
                    # aussieht.
                    flag_names.append("gespeichert (unkomprimiert)")
                size = fe.expanded_size
                csize = fe.compressed_size
            else:
                if fe.compressed:
                    flag_names.append("komprimiert")
                if fe.invalid:
                    flag_names.append("UNGÜLTIG")
                    is_unselectable = True
                    tag = "invalid"
                if fe.partial:
                    flag_names.append("SPLIT/PARTIAL")
                if not flag_names:
                    flag_names.append("gespeichert (unkomprimiert)")
                size = fe.size
                csize = fe.comp_size

            check_symbol = "–" if is_unselectable else CHECK_OFF

            iid = self.tree.insert(
                "", "end",
                values=(
                    check_symbol,
                    fe.name,
                    fe.directory_name,
                    human_size(size),
                    human_size(csize),
                    ", ".join(flag_names),
                ),
                tags=(str(fe.index), tag) if tag else (str(fe.index),),
            )
            self.checked[iid] = False
            if is_unselectable:
                self._invalid_iids.add(iid)

        self._fe_by_index = {str(fe.index): fe for fe in self.header.files}
        self._iid_to_index = {
            iid: self.tree.item(iid, "tags")[0] for iid in self.tree.get_children()
        }

    # -- Checkbox-Handling -------------------------------------------------

    def on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if col == "#1":  # check-Spalte
            self.toggle(iid)
            return "break"

    def on_tree_space(self, event):
        for iid in self.tree.selection():
            self.toggle(iid)

    def toggle(self, iid):
        if iid in self._invalid_iids:
            return  # ungueltige Eintraege koennen nicht ausgewaehlt werden
        self.checked[iid] = not self.checked.get(iid, False)
        self.tree.set(iid, "check", CHECK_ON if self.checked[iid] else CHECK_OFF)

    def select_all(self):
        for iid in self.tree.get_children():
            if iid in self._invalid_iids:
                continue
            self.checked[iid] = True
            self.tree.set(iid, "check", CHECK_ON)

    def select_none(self):
        for iid in self.tree.get_children():
            if iid in self._invalid_iids:
                continue
            self.checked[iid] = False
            self.tree.set(iid, "check", CHECK_OFF)

    # -- Extraktion ----------------------------------------------------

    def on_extract(self):
        if not self.header:
            messagebox.showinfo("Keine Datei", "Bitte zuerst ein Archiv laden.")
            return

        selected_iids = [iid for iid, v in self.checked.items() if v]
        if not selected_iids:
            messagebox.showinfo("Keine Auswahl", "Bitte mindestens eine Datei ankreuzen.")
            return

        out_dir = filedialog.askdirectory(title="Zielverzeichnis wählen")
        if not out_dir:
            return

        entries = [self._fe_by_index[self._iid_to_index[iid]] for iid in selected_iids]

        self.status.config(text="Extrahiere 0/%d ..." % len(entries))
        self.root.update_idletasks()

        errors = []
        done = 0
        error_cls = is5.ISCabError if self.backend == "is5" else is3.IS3Error

        self._cancel_extraction = False
        for fe in entries:
            out_path = os.path.join(out_dir, fe.rel_path.lstrip("/"))
            try:
                if self.backend == "is5" and fe.is_external(self.header):
                    is5.copy_external_file(
                        self.header, fe, out_path,
                        on_missing_source=self._on_missing_source,
                    )
                elif self.backend == "is5":
                    is5.extract_file(
                        self.header, fe, out_path,
                        on_missing_volume=self._on_missing_volume,
                    )
                else:
                    is3.extract_file(
                        self.header, fe, out_path,
                        on_missing_part=self._on_missing_part,
                    )
            except error_cls as e:
                if self._cancel_extraction:
                    self._remove_partial(out_path)
                    break
                errors.append("%s: %s" % (fe.rel_path, e))
            except Exception as e:  # noqa: BLE001
                if self._cancel_extraction:
                    self._remove_partial(out_path)
                    break
                errors.append("%s: %s: %s" % (fe.rel_path, type(e).__name__, e))
            done += 1
            self.status.config(text="Extrahiere %d/%d ..." % (done, len(entries)))
            self.root.update_idletasks()

        if self._cancel_extraction:
            self.status.config(text="Abgebrochen nach %d/%d Dateien (%d Fehler)." % (done, len(entries), len(errors)))
            messagebox.showinfo(
                "Abgebrochen",
                "Extraktion abgebrochen.\n%d von %d Dateien fertig, %d Fehler." % (done, len(entries), len(errors)),
            )
            return

        if errors:
            self.status.config(text="Fertig mit %d Fehler(n)." % len(errors))
            messagebox.showwarning(
                "Fertig mit Fehlern",
                "%d von %d Dateien fehlgeschlagen:\n\n%s"
                % (len(errors), len(entries), "\n".join(errors[:20])),
            )
        else:
            self.status.config(text="Fertig: %d Dateien extrahiert nach %s" % (len(entries), out_dir))
            messagebox.showinfo("Fertig", "%d Dateien erfolgreich extrahiert." % len(entries))

    @staticmethod
    def _remove_partial(path):
        """Halb geschriebene Zieldatei der abgebrochenen Extraktion entfernen."""
        try:
            os.remove(path)
        except OSError:
            pass

    def _on_missing_volume(self, e):
        """Callback fuer is5.extract_file(on_missing_volume=...): wird
        GENAU dann aufgerufen, wenn das vorherige Volume schon fertig
        gelesen/geschrieben ist - der Datentraeger kann also in Ruhe
        gewechselt werden, ohne dass Fortschritt verloren geht. Gibt
        True zurueck, wenn ein Pfad registriert wurde und es weitergehen
        soll, sonst False (bricht die aktuelle Datei ab)."""
        base_name = os.path.basename(self.header.path)
        msg = (
            "%s nicht neben %s gefunden.\n\nBitte zum Fortfahren auf die Datei zeigen."
            % (e.filename, base_name)
        )
        if getattr(e, "context", ""):
            msg += "\n\n[Diagnose] " + e.context
        if not messagebox.askokcancel("Volume fehlt", msg):
            self._cancel_extraction = True
            return False
        chosen = filedialog.askopenfilename(
            title="%s auswählen" % e.filename,
            filetypes=[("CAB-Datei", "*.cab *.CAB"), ("Alle Dateien", "*.*")],
        )
        if not chosen:
            self._cancel_extraction = True
            return False
        self.header.register_volume_path(e.volume_index, chosen)
        return True

    def _on_missing_source(self, fe, searched_dir):
        """Callback fuer is5.copy_external_file(on_missing_source=...):
        wird aufgerufen, wenn eine nicht eingebettete (not_embedded)
        Datei nicht im erwarteten Quellordner liegt - z.B. weil nur ein
        Teilbaum der Original-CD vorliegt. Fragt einmalig nach dem
        richtigen Ordner und merkt sich ihn fuer alle weiteren
        externen Dateien in dieser Sitzung."""
        msg = (
            "'%s' nicht in '%s' gefunden.\n\n"
            "Bitte den Ordner auswählen, in dem die Originaldateien "
            "(z.B. CD-Wurzel/Quellverzeichnis) liegen."
            % (fe.rel_path, searched_dir)
        )
        if not messagebox.askokcancel("Quelldatei fehlt", msg):
            self._cancel_extraction = True
            return False
        folder = filedialog.askdirectory(title="Quellordner auswählen")
        if not folder:
            self._cancel_extraction = True
            return False
        self.header.register_external_source_dir(folder)
        return True

    def _on_missing_part(self, e):
        """Callback fuer is3.extract_file(on_missing_part=...): wird
        aufgerufen, wenn ein benoetigter IS3-Archivteil (z.B. SETUP.2)
        nicht gefunden wird - z.B. weil die Teile auf verschiedenen
        Disketten/Datentraegern liegen."""
        msg = (
            "Archivteil %d ('%s') nicht gefunden.\n\n"
            "Bitte zum Fortfahren auf die Datei zeigen."
            % (e.part_id, e.filename)
        )
        if not messagebox.askokcancel("Archivteil fehlt", msg):
            self._cancel_extraction = True
            return False
        chosen = filedialog.askopenfilename(
            title="%s auswählen" % e.filename,
            filetypes=[("Alle Dateien", "*.*")],
        )
        if not chosen:
            self._cancel_extraction = True
            return False
        self.header.register_part_path(e.part_id, chosen)
        return True


def main():
    root = tk.Tk()
    app = ISCabGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
