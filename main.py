import csv
import hashlib
import os
import sqlite3
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "sentinelguard.db"

def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute("""CREATE TABLE IF NOT EXISTS baseline (
        path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
        modified_ns INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_time TEXT NOT NULL,
        event_type TEXT NOT NULL, path TEXT NOT NULL, old_hash TEXT,
        new_hash TEXT, details TEXT)""")
    conn.commit()
    return conn

def collect(folder):
    folder = Path(folder).resolve()
    if not folder.is_dir():
        raise ValueError("Selected folder does not exist.")
    result = {}
    for current, dirs, files in os.walk(folder, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
        for name in files:
            p = Path(current) / name
            if p.is_symlink() or p.resolve() == DB_PATH.resolve():
                continue
            try:
                st = p.stat()
                rel = p.relative_to(folder).as_posix()
                result[rel] = (digest_file(p), st.st_size, st.st_mtime_ns)
            except (OSError, PermissionError):
                continue
    return result

def log_event(conn, kind, path, old_hash=None, new_hash=None, details=""):
    conn.execute("""INSERT INTO audit_log
        (event_time,event_type,path,old_hash,new_hash,details)
        VALUES (?,?,?,?,?,?)""", (now(), kind, path, old_hash, new_hash, details))

def create_baseline(folder):
    items = collect(folder)
    conn = db()
    try:
        conn.execute("DELETE FROM baseline")
        conn.executemany("INSERT INTO baseline VALUES (?,?,?,?)",
                         [(p, *v) for p, v in items.items()])
        log_event(conn, "BASELINE_CREATED", str(Path(folder).resolve()),
                  details=f"Trusted baseline created for {len(items)} files.")
        conn.commit()
    finally:
        conn.close()
    return len(items)

def scan(folder):
    current = collect(folder)
    conn = db()
    counts = {"ADDED": 0, "MODIFIED": 0, "DELETED": 0, "UNCHANGED": 0}
    events = []
    try:
        rows = conn.execute("SELECT path,sha256 FROM baseline").fetchall()
        baseline = dict(rows)
        if not baseline:
            raise ValueError("No baseline found. Create a baseline first.")
        for rel, (new_hash, size, mtime) in current.items():
            if rel not in baseline:
                kind, old = "ADDED", None
                detail = "File was not present in the trusted baseline."
            elif baseline[rel] != new_hash:
                kind, old = "MODIFIED", baseline[rel]
                detail = "SHA-256 hash differs from the trusted baseline."
            else:
                counts["UNCHANGED"] += 1
                continue
            counts[kind] += 1
            log_event(conn, kind, rel, old, new_hash, detail)
            events.append((kind, rel, detail))
        for rel, old_hash in baseline.items():
            if rel not in current:
                counts["DELETED"] += 1
                detail = "File existed in baseline but is now missing."
                log_event(conn, "DELETED", rel, old_hash, None, detail)
                events.append(("DELETED", rel, detail))
        conn.commit()
    finally:
        conn.close()
    return counts, events

class SentinelGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelGuard | File Integrity Monitoring")
        self.root.geometry("1050x700")
        self.root.minsize(850, 570)
        self.root.configure(bg="#101827")
        self.folder = tk.StringVar()
        self.status = tk.StringVar(value="Ready — select a folder to begin.")
        self.interval = tk.IntVar(value=10)
        self.watch_event = threading.Event()
        self.watch_thread = None
        self._style()
        self._header()
        self._controls()
        self._summary()
        self._table()
        self._footer()
        self.refresh_logs()

    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background="#182437", foreground="#e5edf7",
                    fieldbackground="#182437", rowheight=28, borderwidth=0)
        s.configure("Treeview.Heading", background="#26364d", foreground="#ffffff",
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Treeview", background=[("selected", "#245b8f")])
        s.configure("TButton", font=("Segoe UI", 9, "bold"), padding=8)

    def _header(self):
        top = tk.Frame(self.root, bg="#101827")
        top.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(top, text="SENTINELGUARD", bg="#101827", fg="#61d5c5",
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(top, text="Advanced File Integrity Monitoring • SHA-256 • Audit Trail",
                 bg="#101827", fg="#9fb0c5", font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

    def _controls(self):
        box = tk.Frame(self.root, bg="#182437", padx=14, pady=14)
        box.pack(fill="x", padx=24, pady=12)
        tk.Label(box, text="MONITORED FOLDER", bg="#182437", fg="#9fb0c5",
                 font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w")
        ent = tk.Entry(box, textvariable=self.folder, bg="#0f1928", fg="#e5edf7",
                       insertbackground="white", relief="flat", font=("Segoe UI", 10))
        ent.grid(row=1, column=0, sticky="ew", padx=(0, 10), ipady=8)
        ttk.Button(box, text="Browse", command=self.browse).grid(row=1, column=1, padx=4)
        ttk.Button(box, text="Create Baseline", command=self.baseline).grid(row=1, column=2, padx=4)
        ttk.Button(box, text="Scan Now", command=self.scan_now).grid(row=1, column=3, padx=4)
        ttk.Button(box, text="Start Watch", command=self.start_watch).grid(row=1, column=4, padx=4)
        ttk.Button(box, text="Stop Watch", command=self.stop_watch).grid(row=1, column=5, padx=4)
        box.columnconfigure(0, weight=1)
        tk.Label(box, text="Watch interval (seconds)", bg="#182437", fg="#9fb0c5").grid(row=2, column=0, sticky="w", pady=(12, 0))
        tk.Spinbox(box, from_=2, to=3600, textvariable=self.interval, width=7,
                   bg="#0f1928", fg="#e5edf7", buttonbackground="#26364d",
                   relief="flat").grid(row=2, column=0, sticky="w", pady=(34, 0))

    def _summary(self):
        self.cards = {}
        frame = tk.Frame(self.root, bg="#101827")
        frame.pack(fill="x", padx=24, pady=5)
        for i, (key, color) in enumerate([("ADDED", "#2d9d78"), ("MODIFIED", "#d49a35"),
                                          ("DELETED", "#d45c67"), ("UNCHANGED", "#477eae")]):
            card = tk.Frame(frame, bg="#182437", padx=14, pady=10)
            card.pack(side="left", fill="x", expand=True, padx=(0 if i == 0 else 8, 0))
            tk.Label(card, text=key, bg="#182437", fg="#9fb0c5",
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            value = tk.Label(card, text="—", bg="#182437", fg=color,
                             font=("Segoe UI", 20, "bold"))
            value.pack(anchor="w")
            self.cards[key] = value

    def _table(self):
        wrap = tk.Frame(self.root, bg="#101827")
        wrap.pack(fill="both", expand=True, padx=24, pady=12)
        tk.Label(wrap, text="RECENT SECURITY EVENTS", bg="#101827", fg="#dce7f5",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        cols = ("time", "event", "path", "details")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        for col, label, width in [("time", "TIMESTAMP", 180), ("event", "EVENT", 110),
                                  ("path", "FILE / PATH", 260), ("details", "DETAILS", 390)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        y = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y.set)
        self.tree.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")

    def _footer(self):
        bar = tk.Frame(self.root, bg="#101827")
        bar.pack(fill="x", padx=24, pady=(0, 18))
        tk.Label(bar, textvariable=self.status, bg="#101827", fg="#61d5c5",
                 font=("Segoe UI", 9)).pack(side="left")
        ttk.Button(bar, text="Refresh Logs", command=self.refresh_logs).pack(side="right")
        ttk.Button(bar, text="Export CSV", command=self.export_csv).pack(side="right", padx=8)

    def browse(self):
        p = filedialog.askdirectory()
        if p:
            self.folder.set(p)

    def selected_folder(self):
        p = self.folder.get().strip()
        if not p:
            raise ValueError("Please select a folder first.")
        return Path(p).resolve()

    def run_safe(self, fn):
        try:
            fn()
        except Exception as e:
            messagebox.showerror("SentinelGuard", str(e))
            self.status.set(f"Error: {e}")

    def baseline(self):
        def action():
            n = create_baseline(self.selected_folder())
            self.status.set(f"Trusted baseline created: {n} files recorded.")
            messagebox.showinfo("Baseline created", f"{n} files added to the trusted baseline.")
            self.refresh_logs()
        self.run_safe(action)

    def scan_now(self):
        def action():
            counts, events = scan(self.selected_folder())
            for key, value in counts.items():
                self.cards[key].config(text=str(value))
            self.status.set("Scan completed — " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
            self.refresh_logs()
            if events:
                messagebox.showwarning("Changes detected",
                    "\n".join(f"{kind}: {path}" for kind, path, _ in events[:12]))
        self.run_safe(action)

    def start_watch(self):
        def action():
            self.selected_folder()
            if self.watch_thread and self.watch_thread.is_alive():
                self.status.set("Continuous monitoring is already running.")
                return
            interval = int(self.interval.get())
            if interval < 2:
                raise ValueError("Choose an interval of at least 2 seconds.")
            self.watch_event.clear()
            self.watch_thread = threading.Thread(target=self.watch_loop, args=(interval,), daemon=True)
            self.watch_thread.start()
            self.status.set(f"Continuous monitoring started — every {interval} seconds.")
        self.run_safe(action)

    def watch_loop(self, interval):
        while not self.watch_event.is_set():
            try:
                counts, events = scan(self.folder.get())
                self.root.after(0, lambda c=counts: self.update_counts(c))
                self.root.after(0, self.refresh_logs)
                if events:
                    msg = "\n".join(f"{k}: {p}" for k, p, _ in events[:8])
                    self.root.after(0, lambda m=msg: self.status.set("ALERT — " + m.replace("\n", " | ")))
            except Exception as e:
                self.root.after(0, lambda err=str(e): self.status.set("Monitor error: " + err))
                break
            self.watch_event.wait(interval)

    def update_counts(self, counts):
        for k, v in counts.items():
            self.cards[k].config(text=str(v))

    def stop_watch(self):
        self.watch_event.set()
        self.status.set("Monitoring stop requested.")

    def refresh_logs(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        conn = db()
        try:
            rows = conn.execute("""SELECT event_time,event_type,path,details
                FROM audit_log ORDER BY id DESC LIMIT 250""").fetchall()
        finally:
            conn.close()
        for row in rows:
            self.tree.insert("", "end", values=row)

    def export_csv(self):
        dest = filedialog.asksaveasfilename(defaultextension=".csv",
                 filetypes=[("CSV files", "*.csv")], initialfile="sentinelguard_audit.csv")
        if not dest:
            return
        conn = db()
        try:
            rows = conn.execute("""SELECT id,event_time,event_type,path,old_hash,new_hash,details
                FROM audit_log ORDER BY id DESC""").fetchall()
        finally:
            conn.close()
        with open(dest, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "timestamp", "event", "path", "old_sha256", "new_sha256", "details"])
            writer.writerows(rows)
        self.status.set(f"Audit log exported to {dest}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SentinelGuard(root)
    root.mainloop()
