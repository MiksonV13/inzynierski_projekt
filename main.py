
import os
import json
import uuid
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox


METERS_FILE = "meters.txt"
READINGS_FILE = "readings.txt"

DISPLAY_MAP = {"electricity": "prąd", "water": "woda", "gas": "gaz"}
REVERSE_MAP = {v: k for k, v in DISPLAY_MAP.items()}
NORMALIZE_TO_EN = {"prąd":"electricity","elektryczność":"electricity","woda":"water","gaz":"gas"}


def ensure_files():
    for p in (METERS_FILE, READINGS_FILE):
        if not os.path.exists(p):
            open(p, "w", encoding="utf-8").close()

def jsonl_read(path):
    data = []
    if not os.path.exists(path):
        return data
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return data

def jsonl_append(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def jsonl_write_all(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")


def normalize_kind(k):
    return NORMALIZE_TO_EN.get(k, k)

def load_meters(kind=None):
    meters = [m for m in jsonl_read(METERS_FILE) if not m.get("_deleted")]
    for m in meters:
        m["kind"] = normalize_kind(m.get("kind"))
    if kind:
        meters = [m for m in meters if m.get("kind")==kind]
    return sorted(meters, key=lambda m: m.get("created_at",""))

def load_readings(meter_id=None):
    rows = [r for r in jsonl_read(READINGS_FILE) if not r.get("_deleted")]
    if meter_id is not None:
        rows = [r for r in rows if r.get("meter_id")==meter_id]
    return rows

def add_meter(name, kind_en, tariff):
    obj = {
        "id": str(uuid.uuid4()),
        "name": name,
        "kind": kind_en,  # 'electricity' | 'water' | 'gas'
        "tariff": float(tariff) if (kind_en=="electricity" and tariff is not None) else None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    jsonl_append(METERS_FILE, obj)
    return obj

def update_meter(mid, name, kind_en, tariff):
    items = jsonl_read(METERS_FILE)
    changed=False
    for it in items:
        if it.get("id")==mid and not it.get("_deleted"):
            it["name"]=name
            it["kind"]=kind_en
            it["tariff"]=float(tariff) if (kind_en=="electricity" and tariff not in (None,"")) else None
            it["updated_at"]=datetime.now().isoformat(timespec="seconds")
            changed=True
    if changed:
        jsonl_write_all(METERS_FILE, items)
    return changed

def delete_meter(mid):
    items = jsonl_read(METERS_FILE)
    changed=False
    for it in items:
        if it.get("id")==mid and not it.get("_deleted"):
            it["_deleted"]=True
            changed=True
    if changed:
        jsonl_write_all(METERS_FILE, items)
        # usuń odczyty
        ritems = jsonl_read(READINGS_FILE)
        for r in ritems:
            if r.get("meter_id")==mid and not r.get("_deleted"):
                r["_deleted"]=True
        jsonl_write_all(READINGS_FILE, ritems)
    return changed

def add_reading(meter_id, value, ts):
    obj = {
        "id": str(uuid.uuid4()),
        "meter_id": meter_id,
        "value": float(value),
        "ts": ts,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    jsonl_append(READINGS_FILE, obj)
    return obj

def delete_reading(rid):
    items = jsonl_read(READINGS_FILE)
    changed=False
    for it in items:
        if it.get("id")==rid and not it.get("_deleted"):
            it["_deleted"]=True
            changed=True
    if changed:
        jsonl_write_all(READINGS_FILE, items)
    return changed

def last_two_readings(meter_id):
    rows = load_readings(meter_id)
    rows.sort(key=lambda r: (r.get("ts",""), r.get("id","")), reverse=True)
    return rows[:2]

def history_readings(meter_id):
    rows = load_readings(meter_id)
    rows.sort(key=lambda r: (r.get("ts",""), r.get("id","")))
    return rows


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Licznik mediów – demo ")
        self.geometry("1000x700")
        self.minsize(900,600)
        ensure_files()
        
        self.configure(bg="#f0f0f0")
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background="#f0f0f0", borderwidth=0)
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10))
        style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', '#000000')])
        style.configure('TFrame', background="#ffffff")
        style.configure('TLabel', background="#ffffff", font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=10)
        style.configure('Treeview', font=('Segoe UI', 9), rowheight=28)
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=12)
        self.t_add = ttk.Frame(nb)
        self.t_read = ttk.Frame(nb)
        self.t_cost = ttk.Frame(nb)
        self.t_hist = ttk.Frame(nb)
        nb.add(self.t_add, text="➕ Dodaj licznik")
        nb.add(self.t_read, text="📝 Dodaj odczyt")
        nb.add(self.t_cost, text="⚡ Różnica i koszt (prąd)")
        nb.add(self.t_hist, text="📚 Historia")

        self.build_add()
        self.build_read()
        self.build_cost()
        self.build_hist()


    def build_add(self):
        frm = self.t_add; pad=16

        r1 = ttk.Frame(frm); r1.pack(fill="x", padx=pad, pady=(pad, 8))
        ttk.Label(r1, text="Nazwa licznika:", width=25).pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(r1, textvariable=self.name_var, width=40, font=('Segoe UI', 10)).pack(side="left", padx=6)

        r2 = ttk.Frame(frm); r2.pack(fill="x", padx=pad, pady=8)
        ttk.Label(r2, text="Rodzaj:", width=25).pack(side="left")
        self.kind_var = tk.StringVar(value=DISPLAY_MAP["electricity"])
        self.kind_combo = ttk.Combobox(r2, textvariable=self.kind_var, state="readonly",
                                       values=list(DISPLAY_MAP.values()), width=20, font=('Segoe UI', 10))
        self.kind_combo.pack(side="left", padx=6)

        r3 = ttk.Frame(frm); r3.pack(fill="x", padx=pad, pady=8)
        ttk.Label(r3, text="Taryfa (zł/kWh, tylko prąd):", width=25).pack(side="left")
        self.tariff_var = tk.StringVar()
        ttk.Entry(r3, textvariable=self.tariff_var, width=20, font=('Segoe UI', 10)).pack(side="left", padx=6)

        def on_add():
            name = self.name_var.get().strip()
            kind_display = self.kind_var.get()
            kind_en = REVERSE_MAP.get(kind_display, kind_display)
            tariff_str = self.tariff_var.get().strip()
            tariff = float(tariff_str) if (kind_en=="electricity" and tariff_str) else None
            if not name:
                messagebox.showerror("Błąd", "Podaj nazwę licznika.")
                return
            add_meter(name, kind_en, tariff)
            messagebox.showinfo("OK", "Dodano licznik.")
            self.name_var.set(""); self.tariff_var.set("")
            self.refresh_all()

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(padx=pad, pady=(8, pad))
        ttk.Button(btn_frame, text="➕ Dodaj licznik", command=on_add).pack()

        ttk.Separator(frm, orient="horizontal").pack(fill="x", padx=pad, pady=(pad, 12))
        ttk.Label(frm, text="Istniejące liczniki:", font=('Segoe UI', 11, 'bold')).pack(anchor="w", padx=pad, pady=(0, 8))
        cols=("id","nazwa","rodzaj","taryfa")
        self.tbl_m = ttk.Treeview(frm, columns=cols, show="headings", height=10)
        self.tbl_m.heading("id", text="ID")
        self.tbl_m.heading("nazwa", text="NAZWA")
        self.tbl_m.heading("rodzaj", text="RODZAJ")
        self.tbl_m.heading("taryfa", text="TARYFA (zł/kWh)")
        for c,w in zip(cols,(120,250,120,150)):
            self.tbl_m.column(c, width=w, anchor="center")
        
        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=self.tbl_m.yview)
        self.tbl_m.configure(yscrollcommand=scrollbar.set)
        self.tbl_m.pack(side="left", fill="both", expand=True, padx=(pad, 0), pady=(0, pad))
        scrollbar.pack(side="right", fill="y", padx=(0, pad), pady=(0, pad))

        self.refresh_meters_table()

    def refresh_meters_table(self):
        for i in self.tbl_m.get_children():
            self.tbl_m.delete(i)
        for m in load_meters():
            self.tbl_m.insert("", "end",
                              values=(m["id"][:8], m["name"],
                                      DISPLAY_MAP.get(m["kind"], m["kind"]),
                                      "" if m.get("tariff") is None else f'{float(m["tariff"]):.4f}'))


    def build_read(self):
        frm = self.t_read; pad=16

        ttk.Label(frm, text="Wybierz licznik:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=pad, pady=(pad, 8))
        self.read_sel_var = tk.StringVar()
        self.read_sel = ttk.Combobox(frm, textvariable=self.read_sel_var, state="readonly", width=56, font=('Segoe UI', 10))
        self.read_sel.pack(padx=pad, pady=(0, 12))

        f1 = ttk.Frame(frm); f1.pack(fill="x", padx=pad, pady=8)
        ttk.Label(f1, text="Stan licznika:", width=30).pack(side="left")
        self.read_value = tk.StringVar()
        ttk.Entry(f1, textvariable=self.read_value, width=20, font=('Segoe UI', 10)).pack(side="left", padx=6)

        f2 = ttk.Frame(frm); f2.pack(fill="x", padx=pad, pady=8)
        ttk.Label(f2, text="Data i czas (YYYY-MM-DD HH:MM:SS):", width=30).pack(side="left")
        self.read_ts = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ttk.Entry(f2, textvariable=self.read_ts, width=24, font=('Segoe UI', 10)).pack(side="left", padx=6)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(padx=pad, pady=(12, 8))
        ttk.Button(btn_frame, text="➕ Zapisz odczyt", command=self.save_reading).pack()

        self.last_info = ttk.Label(frm, text="", font=('Segoe UI', 10, 'italic'), foreground="#555555")
        self.last_info.pack(anchor="w", padx=pad, pady=(8, 0))

        self.refresh_read_combo()

    def refresh_read_combo(self):
        meters = load_meters()
        self._meters_cache_r = meters
        opts = [f'{m["name"]} ({DISPLAY_MAP.get(m["kind"], m["kind"])}) [{m["id"][:8]}]' for m in meters]
        self.read_sel["values"] = opts
        if opts:
            self.read_sel.current(0)
        self.update_last_info()
        self.read_sel.bind("<<ComboboxSelected>>", lambda e: self.update_last_info())

    def update_last_info(self):
        idx = self.read_sel.current()
        if idx < 0 or not getattr(self, "_meters_cache_r", None):
            self.last_info.config(text="")
            return
        m = self._meters_cache_r[idx]
        hist = history_readings(m["id"])
        if hist:
            last = hist[-1]
            self.last_info.config(text=f"Ostatni odczyt: {last['value']} z {last['ts']}")
        else:
            self.last_info.config(text="Brak odczytów.")

    def save_reading(self):
        idx = self.read_sel.current()
        if idx < 0:
            messagebox.showerror("Błąd", "Wybierz licznik.")
            return
        m = self._meters_cache_r[idx]
        try:
            val = float(self.read_value.get().replace(",", "."))
        except ValueError:
            messagebox.showerror("Błąd", "Niepoprawna wartość odczytu.")
            return
        ts_str = self.read_ts.get().strip()
        try:
            _ = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            messagebox.showerror("Błąd", "Nieprawidłowy format daty. Użyj YYYY-MM-DD HH:MM:SS.")
            return

        hist = history_readings(m["id"])
        if hist and val < float(hist[-1]["value"]):
            messagebox.showerror("Błąd", "Nowy odczyt jest mniejszy od poprzedniego.")
            return

        add_reading(m["id"], val, ts_str)
        messagebox.showinfo("OK", "Odczyt zapisany.")
        self.read_value.set("")
        self.read_ts.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.refresh_all()


    def build_cost(self):
        frm = self.t_cost; pad=16
        ttk.Label(frm, text="Wybierz licznik prądu:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=pad, pady=(pad, 8))
        self.e_sel_var = tk.StringVar()
        self.e_sel = ttk.Combobox(frm, textvariable=self.e_sel_var, state="readonly", width=48, font=('Segoe UI', 10))
        self.e_sel.pack(padx=pad, pady=(0, 12))
        
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(padx=pad, pady=(8, 16))
        ttk.Button(btn_frame, text="🔄 Przelicz", command=self.calc_cost).pack()
        
        self.cost_label = ttk.Label(frm, text="", font=("Segoe UI", 11), wraplength=900, justify="left")
        self.cost_label.pack(anchor="w", padx=pad, pady=8)
        self.refresh_e_combo()

    def refresh_e_combo(self):
        elec = load_meters(kind="electricity")
        self._meters_cache_e = elec
        opts = [f'{m["name"]} [{m["id"][:8]}]' for m in elec]
        self.e_sel["values"] = opts
        if opts:
            self.e_sel.current(0)
        self.cost_label.config(text="")

    def calc_cost(self):
        idx = self.e_sel.current()
        if idx < 0:
            messagebox.showinfo("Info", "Brak liczników prądu.")
            return
        m = self._meters_cache_e[idx]
        tariff = float(m.get("tariff") or 0.0)
        two = last_two_readings(m["id"])
        if len(two) < 2:
            self.cost_label.config(text="Potrzebne są co najmniej dwa odczyty.")
            return
        curr, prev = two[0], two[1]
        diff = float(curr["value"]) - float(prev["value"])
        if diff < 0:
            self.cost_label.config(text="Wykryto spadek stanu licznika – dane błędne.")
            return
        txt = f"Aktualny: {curr['value']:.3f} (z {curr['ts']}), poprzedni: {prev['value']:.3f} (z {prev['ts']}).\nRóżnica: {diff:.3f} kWh"
        if tariff:
            cost = diff * tariff
            txt += f", taryfa: {tariff:.4f} zł/kWh → koszt: {cost:.2f} zł."
        else:
            txt += ". Brak taryfy – uzupełnij przy dodawaniu licznika."
        self.cost_label.config(text=txt)


    def build_hist(self):
        frm = self.t_hist; pad=16
        ttk.Label(frm, text="Wybierz licznik:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=pad, pady=(pad, 8))
        self.h_sel_var = tk.StringVar()
        self.h_sel = ttk.Combobox(frm, textvariable=self.h_sel_var, state="readonly", width=48, font=('Segoe UI', 10))
        self.h_sel.pack(padx=pad, pady=(0, 12))
        cols=("ts","value","id")
        self.tbl_hist = ttk.Treeview(frm, columns=cols, show="headings", height=16)
        self.tbl_hist.heading("ts", text="DATA")
        self.tbl_hist.heading("value", text="STAN")
        self.tbl_hist.heading("id", text="ID")
        for c,w in zip(cols,(240,120,280)):
            self.tbl_hist.column(c, width=w, anchor="center")
        
        scrollbar_h = ttk.Scrollbar(frm, orient="vertical", command=self.tbl_hist.yview)
        self.tbl_hist.configure(yscrollcommand=scrollbar_h.set)
        self.tbl_hist.pack(side="left", fill="both", expand=True, padx=(pad, 0), pady=(0, 8))
        scrollbar_h.pack(side="right", fill="y", padx=(0, pad), pady=(0, 8))
        
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(pady=(0, pad))
        ttk.Button(btn_frame, text="🗑️ Usuń zaznaczony odczyt", command=self.remove_reading).pack()
        self.refresh_h_combo()

    def refresh_h_combo(self):
        meters = load_meters()
        self._meters_cache_h = meters
        opts = [f'{m["name"]} [{m["id"][:8]}]' for m in meters]
        self.h_sel["values"] = opts
        if opts:
            self.h_sel.current(0)
            self.load_history_table()
        self.h_sel.bind("<<ComboboxSelected>>", lambda e: self.load_history_table())

    def load_history_table(self):
        for i in self.tbl_hist.get_children():
            self.tbl_hist.delete(i)
        idx = self.h_sel.current()
        if idx < 0: return
        m = self._meters_cache_h[idx]
        for r in history_readings(m["id"]):
            self.tbl_hist.insert("", "end", values=(r["ts"], f'{float(r["value"]):.3f}', r["id"]))

    def remove_reading(self):
        sel = self.tbl_hist.selection()
        if not sel:
            messagebox.showinfo("Info", "Zaznacz wiersz do usunięcia.")
            return
        rid = self.tbl_hist.item(sel[0])["values"][2]
        if messagebox.askyesno("Potwierdzenie", "Usunąć wybrany odczyt?"):
            delete_reading(rid)
            self.load_history_table()


    def refresh_all(self):
        self.refresh_meters_table()
        self.refresh_read_combo()
        self.refresh_e_combo()
        self.refresh_h_combo()

if __name__ == "__main__":
    app = App()
    app.mainloop()


