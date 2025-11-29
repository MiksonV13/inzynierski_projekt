import os
import uuid
from datetime import datetime
from decimal import Decimal
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import boto3
import time
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


CURRENT_USER = None

ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "AKIA3HGZKODJZMKBTBXX")
SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "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")
REGION = os.getenv("AWS_REGION", "eu-north-1")

dynamo = boto3.client(
    "dynamodb",
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name=REGION
)


def deserialize_item(item):
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(v) for k, v in item.items()}


def serialize_item(item):
    serializer = TypeSerializer()
    return {k: serializer.serialize(v) for k, v in item.items()}


def ensure_files():
    pass


def load_meters(kind=None):
    if not CURRENT_USER:
        return []
    try:
        resp = dynamo.query(
            TableName="Meters",
            KeyConditionExpression="userEmail = :email",
            ExpressionAttributeValues={":email": {"S": CURRENT_USER}}
        )
        meters = [deserialize_item(m) for m in resp.get("Items", [])]
        if kind:
            meters = [m for m in meters if m.get("type") == kind]
        for m in meters:
            m["id"] = m.get("meterId")
            m["kind"] = m.get("type")
            m["created_at"] = m.get("createdAt")
            m["initial_reading"] = m.get("initialReading")
            m["updated_at"] = m.get("updatedAt")
        return sorted(meters, key=lambda m: m.get("created_at", 0))
    except Exception as e:
        print(f"Error loading meters: {e}")
        return []


def load_readings(meter_id=None):
    if not CURRENT_USER:
        return []
    try:
        resp = dynamo.query(
            TableName="Readings",
            KeyConditionExpression="userEmail = :email",
            ExpressionAttributeValues={":email": {"S": CURRENT_USER}}
        )
        rows = [deserialize_item(r) for r in resp.get("Items", [])]
        if meter_id is not None:
            rows = [r for r in rows if r.get("meterId") == meter_id]
        for r in rows:
            r["id"] = r.get("readingId")
            r["meter_id"] = r.get("meterId")
            r["ts"] = r.get("date")
        return rows
    except Exception as e:
        print(f"Error loading readings: {e}")
        return []


def add_meter(name, kind, tariff, initial_reading):
    if not CURRENT_USER:
        raise Exception("Not logged in")
    try:
        meter_id = str(uuid.uuid4())
        tariff_val = None
        initial_val = None
        
        if tariff not in (None, ""):
            try:
                tariff_val = Decimal(str(tariff))
            except:
                raise Exception("Proszę wpisać liczbę")
        if initial_reading not in (None, ""):
            try:
                initial_val = Decimal(str(initial_reading))
            except:
                raise Exception("Proszę wpisać liczbę")
        
        item = {
            "userEmail": CURRENT_USER,
            "meterId": meter_id,
            "name": name,
            "type": kind,
            "tariff": tariff_val,
            "initialReading": initial_val,
            "createdAt": int(time.time())
        }
        dynamo.put_item(TableName="Meters", Item=serialize_item(item))
        item["id"] = meter_id
        item["kind"] = kind
        item["created_at"] = item["createdAt"]
        return item
    except Exception as e:
        raise Exception(f"Failed to add meter: {e}")


def update_meter(mid, name, kind, tariff, initial_reading):
    if not CURRENT_USER:
        return False
    try:
        try:
            tariff_val = None if tariff in (None, "") else Decimal(str(tariff))
        except:
            raise Exception("Proszę wpisać liczbę")
        try:
            initial_val = None if initial_reading in (None, "") else Decimal(str(initial_reading))
        except:
            raise Exception("Proszę wpisać liczbę")
        
        update_expr = []
        expr_values = {}
        expr_names = {}
        
        updates = {
            "name": name,
            "type": kind,
            "tariff": tariff_val,
            "initialReading": initial_val
        }
        
        for k, v in updates.items():
            update_expr.append(f"#{k} = :{k}")
            expr_names[f"#{k}"] = k
            expr_values[f":{k}"] = serialize_item({k: v})[k]
        
        dynamo.update_item(
            TableName="Meters",
            Key=serialize_item({"userEmail": CURRENT_USER, "meterId": mid}),
            UpdateExpression="SET " + ", ".join(update_expr),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        return True
    except Exception as e:
        raise Exception(f"Error updating meter: {e}")


def delete_meter(mid):
    if not CURRENT_USER:
        return False
    try:
        dynamo.delete_item(
            TableName="Meters",
            Key=serialize_item({"userEmail": CURRENT_USER, "meterId": mid})
        )
        resp = dynamo.query(
            TableName="Readings",
            KeyConditionExpression="userEmail = :email",
            ExpressionAttributeValues={":email": {"S": CURRENT_USER}}
        )
        for r in resp.get("Items", []):
            r_deser = deserialize_item(r)
            if r_deser.get("meterId") == mid:
                dynamo.delete_item(
                    TableName="Readings",
                    Key=serialize_item({"userEmail": CURRENT_USER, "readingId": r_deser.get("readingId")})
                )
        return True
    except Exception as e:
        print(f"Error deleting meter: {e}")
        return False


def add_reading(meter_id, value, ts):
    if not CURRENT_USER:
        raise Exception("Not logged in")
    try:
        reading_id = str(uuid.uuid4())
        try:
            value_decimal = Decimal(str(value))
        except:
            raise Exception("Proszę wpisać liczbę")
        item = {
            "userEmail": CURRENT_USER,
            "readingId": reading_id,
            "meterId": meter_id,
            "value": value_decimal,
            "date": ts,
            "createdAt": int(time.time())
        }
        dynamo.put_item(TableName="Readings", Item=serialize_item(item))
        item["id"] = reading_id
        item["meter_id"] = meter_id
        item["ts"] = ts
        return item
    except Exception as e:
        raise Exception(f"Failed to add reading: {e}")


def delete_reading(rid):
    if not CURRENT_USER:
        return False
    try:
        dynamo.delete_item(
            TableName="Readings",
            Key=serialize_item({"userEmail": CURRENT_USER, "readingId": rid})
        )
        return True
    except Exception as e:
        print(f"Error deleting reading: {e}")
        return False



def last_two_readings(meter_id):
    meters = load_meters()
    meter = next((m for m in meters if m["id"] == meter_id), None)

    rows = load_readings(meter_id)
    rows.sort(key=lambda r: (r.get("ts", ""), r.get("id", "")))

    all_readings = []
    if meter and meter.get("initial_reading") is not None:
        all_readings.append({
            "value": meter["initial_reading"],
            "ts": "Odczyt początkowy",
            "id": "initial"
        })
    all_readings.extend(rows)

    if len(all_readings) >= 2:
        return [all_readings[-1], all_readings[-2]]
    return all_readings


def history_readings(meter_id):
    rows = load_readings(meter_id)
    rows.sort(key=lambda r: (r.get("ts", ""), r.get("id", "")))
    return rows


BASE_URL = "https://2wc2plq72h.execute-api.eu-north-1.amazonaws.com/default"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Licznik mediów")
        self.geometry("1200x800")
        self.minsize(1000, 650)
        self.token = None
        self.current_user = None
        ensure_files()

        self.configure(bg="#E3F2FD")
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('LoginFrame.TFrame', background="#E3F2FD")
        style.configure('LoginLabel.TLabel', background="#E3F2FD", font=('Segoe UI', 10), foreground="#1565C0")
        style.configure('TNotebook', background="#E3F2FD", borderwidth=0)
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10), background="#BBDEFB")
        style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', '#1976D2')])
        style.configure('TFrame', background="#ffffff")
        style.configure('TLabel', background="#ffffff", font=('Segoe UI', 10), foreground="#1565C0")
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=10, background="#1976D2",
                        foreground="#ffffff")
        style.map('TButton', background=[('active', '#1565C0')])
        style.configure('Treeview', font=('Segoe UI', 9), rowheight=28, background="#ffffff", fieldbackground="#ffffff")
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'), background="#1976D2", foreground="#ffffff")
        style.map('Treeview.Heading', background=[('active', '#1565C0')])
        
        self.login_frame = None
        self.app_frame = None
        self.show_login()
    
    def _is_valid_number(self, value):
        try:
            float(value.replace(",", "."))
            return True
        except ValueError:
            return False
    
    def show_login(self):
        if self.app_frame:
            self.app_frame.pack_forget()
        
        if self.login_frame:
            self.login_frame.pack(fill="both", expand=True)
            return
        
        self.geometry("400x300")
        
        self.login_frame = ttk.Frame(self, style='LoginFrame.TFrame')
        self.login_frame.pack(fill="both", expand=True)
        
        outer_frame = ttk.Frame(self.login_frame, style='LoginFrame.TFrame')
        outer_frame.pack(fill="both", expand=True, padx=100, pady=20)
        
        center_frame = ttk.Frame(outer_frame, style='LoginFrame.TFrame')
        center_frame.pack(fill="both", expand=True)
        
        title = ttk.Label(center_frame, text="Licznik mediów", font=('Segoe UI', 14, 'bold'), foreground="#1976D2", style='LoginLabel.TLabel')
        title.pack(pady=(40, 20))
        
        ttk.Label(center_frame, text="Login:", font=('Segoe UI', 9), style='LoginLabel.TLabel').pack(anchor="w", pady=(0, 2))
        self.email_var = tk.StringVar()
        ttk.Entry(center_frame, textvariable=self.email_var, width=32, font=('Segoe UI', 10)).pack(fill="x", pady=(0, 8))
        
        ttk.Label(center_frame, text="Hasło:", font=('Segoe UI', 9), style='LoginLabel.TLabel').pack(anchor="w", pady=(0, 2))
        self.password_var = tk.StringVar()
        ttk.Entry(center_frame, textvariable=self.password_var, width=32, show="*", font=('Segoe UI', 10)).pack(fill="x", pady=(0, 14))
        
        button_frame = ttk.Frame(center_frame, style='LoginFrame.TFrame')
        button_frame.pack(fill="x", pady=(0, 8))
        ttk.Button(button_frame, text="Zaloguj", command=self.do_login).pack(side="left", padx=(0, 6), expand=True, fill="x")
        ttk.Button(button_frame, text="Zarejestruj", command=self.do_register).pack(side="left", expand=True, fill="x")
        
        self.status_label = ttk.Label(center_frame, text="", font=('Segoe UI', 8), foreground="#D32F2F", style='LoginLabel.TLabel')
        self.status_label.pack(pady=(0, 0))
    
    def do_login(self):
        global CURRENT_USER
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        
        if not email or not password:
            self.status_label.config(text="Podaj login i hasło", foreground="#D32F2F")
            return
        
        self.status_label.config(text="Logowanie...", foreground="#1976D2")
        self.update()
        
        try:
            response = requests.post(f"{BASE_URL}/login", json={"email": email, "password": password}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                self.current_user = email
                CURRENT_USER = email
                ensure_files()
                self.status_label.config(text="Zalogowano!", foreground="#388E3C")
                self.after(500, self.show_app)
            else:
                self.status_label.config(text="Niepoprawne dane", foreground="#D32F2F")
        except Exception as e:
            self.status_label.config(text=f"Błąd: {str(e)[:30]}", foreground="#D32F2F")
    
    def do_register(self):
        global CURRENT_USER
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        
        if not email or not password:
            self.status_label.config(text="Podaj login i hasło", foreground="#D32F2F")
            return
        
        if len(password) < 6:
            self.status_label.config(text="Hasło musi mieć min. 6 znaków", foreground="#D32F2F")
            return
        
        self.status_label.config(text="Rejestracja...", foreground="#1976D2")
        self.update()
        
        try:
            response = requests.post(f"{BASE_URL}/register", json={"email": email, "password": password}, timeout=5)
            if 200 <= response.status_code < 300:
                response2 = requests.post(f"{BASE_URL}/login", json={"email": email, "password": password}, timeout=5)
                if response2.status_code == 200:
                    data = response2.json()
                    self.token = data.get("token")
                    self.current_user = email
                    CURRENT_USER = email
                    ensure_files()
                    self.status_label.config(text="User registered successfully", foreground="#388E3C")
                    self.after(500, self.show_app)
                else:
                    self.status_label.config(text="Błąd logowania", foreground="#D32F2F")
            else:
                try:
                    resp_text = response.json().get("message", response.text)
                except:
                    resp_text = response.text
                
                if "exists" in resp_text.lower() or response.status_code == 409:
                    self.status_label.config(text="Konto istnieje. Zaloguj się.", foreground="#F57C00")
                else:
                    self.status_label.config(text=f"Błąd: {resp_text[:30]}", foreground="#D32F2F")
        except Exception as e:
            self.status_label.config(text=f"Błąd: {str(e)[:30]}", foreground="#D32F2F")
    
    def show_app(self):
        if self.login_frame:
            self.login_frame.pack_forget()
        
        self.geometry("1200x800")
        
        if self.app_frame:
            self.app_frame.pack(fill="both", expand=True)
            self.refresh_meters_table()
            self.refresh_read_combo()
            self.refresh_e_combo()
            self.refresh_w_combo()
            self.refresh_g_combo()
            self.refresh_edit_table()
            return
        
        self.app_frame = ttk.Frame(self)
        self.app_frame.pack(fill="both", expand=True)
        
        nb = ttk.Notebook(self.app_frame)
        nb.pack(fill="both", expand=True, padx=12, pady=12)
        self.t_add = ttk.Frame(nb)
        self.t_read = ttk.Frame(nb)
        self.t_cost = ttk.Frame(nb)
        self.t_hist = ttk.Frame(nb)
        self.t_edit = ttk.Frame(nb)
        self.t_chart = ttk.Frame(nb)
        nb.add(self.t_add, text="➕ Dodaj licznik")
        nb.add(self.t_read, text="📝 Dodaj odczyt")
        nb.add(self.t_chart, text="📊 Zużycie")
        nb.add(self.t_cost, text="💰 Koszty")
        nb.add(self.t_hist, text="📚 Historia")
        nb.add(self.t_edit, text="✏️ Edycja")

        self.build_add()
        self.build_read()
        self.build_cost()
        self.build_hist()
        self.build_edit()
        self.build_chart()
        
        bottom_bar = ttk.Frame(self.app_frame)
        bottom_bar.pack(fill="x", padx=12, pady=(0, 12))
        
        user_label = ttk.Label(bottom_bar, text=f"Zalogowany: {self.current_user}", font=('Segoe UI', 10, 'bold'), foreground="#1976D2")
        user_label.pack(side="left", expand=True)
        
        ttk.Button(bottom_bar, text="🚪 Wyloguj", command=self.do_logout).pack(side="right")
    
    def do_logout(self):
        global CURRENT_USER
        if messagebox.askyesno("Wylogowanie", "Na pewno chcesz się wylogować?"):
            self.token = None
            self.current_user = None
            CURRENT_USER = None
            self.email_var.set("")
            self.password_var.set("")
            self.status_label.config(text="")
            if self.app_frame:
                self.app_frame.pack_forget()
                self.app_frame.destroy()
                self.app_frame = None
            self.geometry("400x300")
            self.show_login()

    def build_add(self):
        frm = self.t_add;
        pad = 16

        r1 = ttk.Frame(frm);
        r1.pack(fill="x", padx=pad, pady=(pad, 8))
        ttk.Label(r1, text="Nazwa licznika:", width=25).pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(r1, textvariable=self.name_var, width=40, font=('Segoe UI', 10)).pack(side="left", padx=6)

        r2 = ttk.Frame(frm);
        r2.pack(fill="x", padx=pad, pady=8)
        ttk.Label(r2, text="Rodzaj:", width=25).pack(side="left")
        self.kind_var = tk.StringVar(value="prąd")
        self.kind_combo = ttk.Combobox(r2, textvariable=self.kind_var, state="readonly",
                                       values=["prąd", "woda", "gaz"], width=20, font=('Segoe UI', 10))
        self.kind_combo.pack(side="left", padx=6)
        self.kind_combo.bind("<<ComboboxSelected>>", self.update_tariff_label)

        r3 = ttk.Frame(frm);
        r3.pack(fill="x", padx=pad, pady=8)
        self.tariff_label = ttk.Label(r3, text="Taryfa (zł/kWh):", width=25)
        self.tariff_label.pack(side="left")
        self.tariff_var = tk.StringVar()
        ttk.Entry(r3, textvariable=self.tariff_var, width=20, font=('Segoe UI', 10)).pack(side="left", padx=6)

        r4 = ttk.Frame(frm);
        r4.pack(fill="x", padx=pad, pady=8)
        ttk.Label(r4, text="Odczyt początkowy:", width=25).pack(side="left")
        self.initial_reading_var = tk.StringVar()
        ttk.Entry(r4, textvariable=self.initial_reading_var, width=20, font=('Segoe UI', 10)).pack(side="left", padx=6)

        def on_add():
            try:
                name = self.name_var.get().strip()
                kind = self.kind_var.get()
                tariff_str = self.tariff_var.get().strip()
                initial_str = self.initial_reading_var.get().strip()
                if not name:
                    messagebox.showerror("Błąd", "Podaj nazwę licznika.")
                    return
                
                errors = []
                if tariff_str and not self._is_valid_number(tariff_str):
                    errors.append("taryfa")
                if initial_str and not self._is_valid_number(initial_str):
                    errors.append("odczyt początkowy")
                
                if errors:
                    if len(errors) == 1:
                        msg = f"Proszę wpisać liczbę w {errors[0]}"
                    else:
                        msg = f"Proszę wpisać liczby w {' oraz '.join(errors)}"
                    messagebox.showerror("Błąd", msg)
                    return
                
                add_meter(name, kind, tariff_str, initial_str)
                messagebox.showinfo("OK", "Dodano licznik.")
                self.name_var.set("");
                self.tariff_var.set("")
                self.initial_reading_var.set("")
                self.refresh_all()
            except Exception as e:
                error_msg = str(e)
                if "Failed to add meter: " in error_msg:
                    error_msg = error_msg.replace("Failed to add meter: ", "")
                messagebox.showerror("Błąd", error_msg)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(padx=pad, pady=(8, pad))
        ttk.Button(btn_frame, text="➕ Dodaj licznik", command=on_add).pack()

        ttk.Separator(frm, orient="horizontal").pack(fill="x", padx=pad, pady=(pad, 12))
        ttk.Label(frm, text="Istniejące liczniki:", font=('Segoe UI', 11, 'bold')).pack(anchor="w", padx=pad,
                                                                                        pady=(0, 8))
        cols = ("nazwa", "rodzaj", "taryfa", "najnowszy_stan")
        self.tbl_m = ttk.Treeview(frm, columns=cols, show="headings", height=10)
        self.tbl_m.heading("nazwa", text="NAZWA")
        self.tbl_m.heading("rodzaj", text="RODZAJ")
        self.tbl_m.heading("taryfa", text="TARYFA")
        self.tbl_m.heading("najnowszy_stan", text="NAJNOWSZY STAN")
        for c, w in zip(cols, (200, 100, 120, 150)):
            self.tbl_m.column(c, width=w, anchor="center")

        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=self.tbl_m.yview)
        self.tbl_m.configure(yscrollcommand=scrollbar.set)
        self.tbl_m.pack(side="left", fill="both", expand=True, padx=(pad, 0), pady=(0, pad))
        scrollbar.pack(side="right", fill="y", padx=(0, pad), pady=(0, pad))

        self.refresh_meters_table()

    def update_tariff_label(self, event=None):
        kind = self.kind_var.get()
        if kind == "prąd":
            self.tariff_label.config(text="Taryfa (zł/kWh):")
        elif kind == "woda":
            self.tariff_label.config(text="Taryfa (zł/m³):")
        elif kind == "gaz":
            self.tariff_label.config(text="Taryfa (zł/m³):")
        else:
            self.tariff_label.config(text="Taryfa:")

    def refresh_meters_table(self):
        for i in self.tbl_m.get_children():
            self.tbl_m.delete(i)
        for m in load_meters():
            hist = history_readings(m["id"])
            if hist:
                newest_state = f'{float(hist[-1]["value"]):.3f}'
            else:
                initial = m.get("initial_reading")
                newest_state = f'{float(initial):.3f}' if initial is not None else "-"

            kind = m["kind"]
            if m.get("tariff") is not None:
                if kind == "prąd":
                    tariff_text = f'{float(m["tariff"]):.2f} zł/kWh'
                elif kind in ("woda", "gaz"):
                    tariff_text = f'{float(m["tariff"]):.2f} zł/m³'
                else:
                    tariff_text = f'{float(m["tariff"]):.2f}'
            else:
                tariff_text = ""

            self.tbl_m.insert("", "end",
                              values=(m["name"],
                                      m["kind"],
                                      tariff_text,
                                      newest_state))

    def build_read(self):
        frm = self.t_read;
        pad = 16

        ttk.Label(frm, text="Wybierz licznik:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=pad, pady=(pad, 8))
        self.read_sel_var = tk.StringVar()
        self.read_sel = ttk.Combobox(frm, textvariable=self.read_sel_var, state="readonly", width=56,
                                     font=('Segoe UI', 10))
        self.read_sel.pack(padx=pad, pady=(0, 12))

        f1 = ttk.Frame(frm);
        f1.pack(fill="x", padx=pad, pady=8)
        ttk.Label(f1, text="Stan licznika:", width=30).pack(side="left")
        self.read_value = tk.StringVar()
        ttk.Entry(f1, textvariable=self.read_value, width=20, font=('Segoe UI', 10)).pack(side="left", padx=6)

        self.read_ts = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(padx=pad, pady=(12, 8))
        ttk.Button(btn_frame, text="➕ Zapisz odczyt", command=self.save_reading).pack()

        self.last_info = ttk.Label(frm, text="", font=('Segoe UI', 10, 'italic'), foreground="#555555")
        self.last_info.pack(anchor="w", padx=pad, pady=(8, 0))

        self.refresh_read_combo()

    def refresh_read_combo(self):
        meters = load_meters()
        self._meters_cache_r = meters
        opts = [f'{m["name"]} ({m["kind"]})' for m in meters]
        self.read_sel["values"] = opts
        if opts:
            self.read_sel.current(len(opts) - 1)
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
            initial = m.get("initial_reading")
            if initial is not None:
                self.last_info.config(text=f"Odczyt początkowy: {initial}")
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
            messagebox.showerror("Błąd", "Proszę wpisać liczbę w wartość odczytu")
            return
        ts_str = self.read_ts.get().strip()
        try:
            _ = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            messagebox.showerror("Błąd", "Nieprawidłowy format daty. Użyj YYYY-MM-DD HH:MM:SS.")
            return

        hist = history_readings(m["id"])
        initial = m.get("initial_reading")

        last_value = None
        if hist:
            last_value = float(hist[-1]["value"])
        elif initial is not None:
            last_value = float(initial)

        if last_value is not None and val < last_value:
            messagebox.showerror("Błąd", "Nowy odczyt jest mniejszy od poprzedniego.")
            return

        try:
            add_reading(m["id"], val, ts_str)
            messagebox.showinfo("OK", "Odczyt zapisany.")
            self.read_value.set("")
            self.read_ts.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.refresh_all()
        except Exception as e:
            error_msg = str(e)
            if "Failed to add reading: " in error_msg:
                error_msg = error_msg.replace("Failed to add reading: ", "")
            messagebox.showerror("Błąd", error_msg)

    def build_cost(self):
        frm = self.t_cost
        pad = 16

        main_frame = ttk.Frame(frm)
        main_frame.pack(fill="both", expand=True, padx=pad, pady=pad)

        left_menu = ttk.Frame(main_frame, relief="sunken", borderwidth=1)
        left_menu.pack(side="left", fill="y", padx=(0, 12))

        ttk.Label(left_menu, text="Wybierz typ:", font=('Segoe UI', 10, 'bold'),
                  foreground="#1976D2").pack(anchor="w", padx=12, pady=(12, 8))

        self.cost_type_var = tk.StringVar(value="prąd")

        for kind_name, emoji in [("prąd", "⚡"), ("woda", "💧"), ("gaz", "🔥")]:
            btn = ttk.Button(left_menu, text=f"{emoji} {kind_name.upper()}",
                             command=lambda k=kind_name: self._switch_cost_type(k))
            btn.pack(fill="x", padx=8, pady=4)

        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side="left", fill="both", expand=True)

        info_frame = ttk.Frame(right_panel)
        info_frame.pack(fill="x", padx=8, pady=(0, 8))

        ttk.Label(info_frame, text="Wybierz licznik:", font=('Segoe UI', 10)).pack(anchor="w", pady=(0, 4))

        self.cost_combo_frame = ttk.Frame(info_frame)
        self.cost_combo_frame.pack(fill="x")

        self.e_sel_var = tk.StringVar()
        self.w_sel_var = tk.StringVar()
        self.g_sel_var = tk.StringVar()

        self.e_sel = ttk.Combobox(self.cost_combo_frame, textvariable=self.e_sel_var, state="readonly",
                                  width=40, font=('Segoe UI', 10))
        self.w_sel = ttk.Combobox(self.cost_combo_frame, textvariable=self.w_sel_var, state="readonly",
                                  width=40, font=('Segoe UI', 10))
        self.g_sel = ttk.Combobox(self.cost_combo_frame, textvariable=self.g_sel_var, state="readonly",
                                  width=40, font=('Segoe UI', 10))

        self.e_sel.bind("<<ComboboxSelected>>", lambda e: self.calc_cost_elec())
        self.w_sel.bind("<<ComboboxSelected>>", lambda e: self.calc_cost_water())
        self.g_sel.bind("<<ComboboxSelected>>", lambda e: self.calc_cost_gas())

        self.cost_label_elec = ttk.Label(info_frame, text="", font=("Segoe UI", 11, "bold"),
                                         foreground="#D32F2F")
        self.cost_label_water = ttk.Label(info_frame, text="", font=("Segoe UI", 11, "bold"),
                                          foreground="#0277BD")
        self.cost_label_gas = ttk.Label(info_frame, text="", font=("Segoe UI", 11, "bold"),
                                        foreground="#F57C00")

        btn_frame = ttk.Frame(right_panel)
        btn_frame.pack(padx=8, pady=(8, 12), fill="x")
        ttk.Button(btn_frame, text="📊 Porównanie", command=lambda: self._switch_cost_chart_type("comparison")).pack(
            side="left", padx=4)
        ttk.Button(btn_frame, text="📈 Historia", command=lambda: self._switch_cost_chart_type("history")).pack(side="left",
                                                                                                          padx=4)
        ttk.Button(btn_frame, text="🔄 Odśwież", command=self.update_cost_chart).pack(side="left", padx=4)

        chart_frame = ttk.LabelFrame(right_panel, text="Wykres kosztów")
        chart_frame.pack(fill="both", expand=True, padx=8, pady=(0, 0))

        self.cost_chart_e_frame = ttk.Frame(chart_frame)
        self.cost_chart_w_frame = ttk.Frame(chart_frame)
        self.cost_chart_g_frame = ttk.Frame(chart_frame)

        self._cost_chart_type = "comparison"
        self.refresh_e_combo()
        self.refresh_w_combo()
        self.refresh_g_combo()
        self._switch_cost_type("prąd")

    def _switch_cost_type(self, kind):
        self.e_sel.pack_forget()
        self.w_sel.pack_forget()
        self.g_sel.pack_forget()
        
        self.cost_chart_e_frame.pack_forget()
        self.cost_chart_w_frame.pack_forget()
        self.cost_chart_g_frame.pack_forget()
        
        self.cost_type_var.set(kind)
        
        if kind == "prąd":
            self.e_sel.pack(in_=self.cost_combo_frame, fill="x")
            self.cost_chart_e_frame.pack(fill="both", expand=True)
            self.calc_cost_elec()
        elif kind == "woda":
            self.w_sel.pack(in_=self.cost_combo_frame, fill="x")
            self.cost_chart_w_frame.pack(fill="both", expand=True)
            self.calc_cost_water()
        else:
            self.g_sel.pack(in_=self.cost_combo_frame, fill="x")
            self.cost_chart_g_frame.pack(fill="both", expand=True)
            self.calc_cost_gas()

    def refresh_e_combo(self):
        elec = load_meters(kind="prąd")
        self._meters_cache_e = elec
        opts = [f'{m["name"]}' for m in elec]
        self.e_sel["values"] = opts
        if opts:
            self.e_sel.current(0)
            self.calc_cost_elec()

    def refresh_w_combo(self):
        water = load_meters(kind="woda")
        self._meters_cache_w = water
        opts = [f'{m["name"]}' for m in water]
        self.w_sel["values"] = opts
        if opts:
            self.w_sel.current(0)
            self.calc_cost_water()

    def refresh_g_combo(self):
        gas = load_meters(kind="gaz")
        self._meters_cache_g = gas
        opts = [f'{m["name"]}' for m in gas]
        self.g_sel["values"] = opts
        if opts:
            self.g_sel.current(0)
            self.calc_cost_gas()

    def _switch_cost_chart_type(self, chart_type):
        self._cost_chart_type = chart_type
        self.update_cost_chart()

    def update_cost_chart(self):
        if self.cost_type_var.get() == "prąd":
            self.calc_cost_elec()
        elif self.cost_type_var.get() == "woda":
            self.calc_cost_water()
        else:
            self.calc_cost_gas()

    def calc_cost_elec(self):
        idx = self.e_sel.current()
        if idx < 0:
            self._clear_cost_chart("elec")
            return
        m = self._meters_cache_e[idx]
        tariff = float(m.get("tariff") or 0.0)
        hist = history_readings(m["id"])
        initial = m.get("initial_reading")
        total_readings = len(hist) + (1 if initial is not None else 0)

        if total_readings < 2:
            self._clear_cost_chart("elec", show_message=True)
            return

        if getattr(self, '_cost_chart_type', 'comparison') == "comparison":
            curr = float(hist[-1]["value"])

            if len(hist) == 1:
                prev = float(initial) if initial is not None else curr
                before_prev = prev
                diff_curr = curr - prev
                diff_prev = 0
            else:
                prev = float(hist[-2]["value"])
                before_prev = float(hist[-3]["value"]) if len(hist) >= 3 else (
                    float(initial) if initial is not None else prev)
                diff_curr = curr - prev
                diff_prev = prev - before_prev

            if diff_curr < 0 or diff_prev < 0:
                self._clear_cost_chart("elec")
                return

            cost_curr = diff_curr * tariff if tariff else 0
            cost_prev = diff_prev * tariff if tariff else 0
            self.after(100, lambda cost_curr=cost_curr, cost_prev=cost_prev: self._draw_cost_chart("elec", cost_curr, cost_prev, "comparison"))
        else:
            self.after(100, lambda m=m, hist=hist, initial=initial, tariff=tariff: self._draw_cost_history_chart("elec", m, hist, initial, tariff))

    def calc_cost_water(self):
        idx = self.w_sel.current()
        if idx < 0:
            self._clear_cost_chart("water")
            return
        m = self._meters_cache_w[idx]
        tariff = float(m.get("tariff") or 0.0)
        hist = history_readings(m["id"])
        initial = m.get("initial_reading")
        total_readings = len(hist) + (1 if initial is not None else 0)

        if total_readings < 2:
            self._clear_cost_chart("water", show_message=True)
            return

        if getattr(self, '_cost_chart_type', 'comparison') == "comparison":
            curr = float(hist[-1]["value"])

            if len(hist) == 1:
                prev = float(initial) if initial is not None else curr
                before_prev = prev
                diff_curr = curr - prev
                diff_prev = 0
            else:
                prev = float(hist[-2]["value"])
                before_prev = float(hist[-3]["value"]) if len(hist) >= 3 else (
                    float(initial) if initial is not None else prev)
                diff_curr = curr - prev
                diff_prev = prev - before_prev

            if diff_curr < 0 or diff_prev < 0:
                self._clear_cost_chart("water")
                return

            cost_curr = diff_curr * tariff if tariff else 0
            cost_prev = diff_prev * tariff if tariff else 0
            self.after(100, lambda cost_curr=cost_curr, cost_prev=cost_prev: self._draw_cost_chart("water", cost_curr, cost_prev, "comparison"))
        else:
            self.after(100, lambda m=m, hist=hist, initial=initial, tariff=tariff: self._draw_cost_history_chart("water", m, hist, initial, tariff))

    def calc_cost_gas(self):
        idx = self.g_sel.current()
        if idx < 0:
            self._clear_cost_chart("gas")
            return
        m = self._meters_cache_g[idx]
        tariff = float(m.get("tariff") or 0.0)
        hist = history_readings(m["id"])
        initial = m.get("initial_reading")
        total_readings = len(hist) + (1 if initial is not None else 0)

        if total_readings < 2:
            self._clear_cost_chart("gas", show_message=True)
            return

        if getattr(self, '_cost_chart_type', 'comparison') == "comparison":
            curr = float(hist[-1]["value"])

            if len(hist) == 1:
                prev = float(initial) if initial is not None else curr
                before_prev = prev
                diff_curr = curr - prev
                diff_prev = 0
            else:
                prev = float(hist[-2]["value"])
                before_prev = float(hist[-3]["value"]) if len(hist) >= 3 else (
                    float(initial) if initial is not None else prev)
                diff_curr = curr - prev
                diff_prev = prev - before_prev

            if diff_curr < 0 or diff_prev < 0:
                self._clear_cost_chart("gas")
                return

            cost_curr = diff_curr * tariff if tariff else 0
            cost_prev = diff_prev * tariff if tariff else 0
            self.after(100, lambda cost_curr=cost_curr, cost_prev=cost_prev: self._draw_cost_chart("gas", cost_curr, cost_prev, "comparison"))
        else:
            self.after(100, lambda m=m, hist=hist, initial=initial, tariff=tariff: self._draw_cost_history_chart("gas", m, hist, initial, tariff))

    def _clear_cost_chart(self, kind, show_message=False):
        if kind == "elec":
            frame = self.cost_chart_e_frame
        elif kind == "water":
            frame = self.cost_chart_w_frame
        else:
            frame = self.cost_chart_g_frame
        for widget in frame.winfo_children():
            widget.destroy()
        
        if show_message:
            ttk.Label(frame, text="Potrzebne są co najmniej 2 odczyty do wyświetlenia wykresu.",
                      font=('Segoe UI', 10)).pack(padx=16, pady=16)

    def _draw_cost_chart(self, kind, current_cost, previous_cost, chart_type):
        if kind == "elec":
            frame = self.cost_chart_e_frame
        elif kind == "water":
            frame = self.cost_chart_w_frame
        else:
            frame = self.cost_chart_g_frame

        for widget in frame.winfo_children():
            widget.destroy()

        frame_w = frame.winfo_width()
        frame_h = frame.winfo_height()

        if frame_w < 50:
            frame_w = 600
        if frame_h < 50:
            frame_h = 300

        dpi = 100
        figsize_w = max(frame_w / dpi * 0.95, 4)
        figsize_h = max(frame_h / dpi * 0.95, 2.5)

        fig = Figure(figsize=(figsize_w, figsize_h), dpi=dpi)
        fig.patch.set_facecolor('white')

        ax = fig.add_subplot(111)
        fig.subplots_adjust(left=0.1, right=0.95, top=0.85, bottom=0.15)

        if previous_cost == 0 or previous_cost < 0.01:
            labels = ['Bieżący\nokres']
            costs = [current_cost]
            colors = ['#1976D2']
            edgecolors = ['#1565C0']
            bars = ax.bar([0], costs, color=colors, edgecolor=edgecolors, linewidth=2, width=0.6)
            ax.set_xlim(-1, 1)
            ax.set_xticks([0])
            ax.set_xticklabels(labels)
        else:
            labels = ['Poprzedni\nokres', 'Bieżący\nokres']
            costs = [previous_cost, current_cost]
            colors = ['#FF6B6B', '#1976D2']
            edgecolors = ['#D32F2F', '#1565C0']
            bars = ax.bar(labels, costs, color=colors, edgecolor=edgecolors, linewidth=2, width=0.6)

        ax.set_ylabel('Koszt (zł)', fontsize=11, fontweight='bold')
        ax.set_title('Porównanie kosztów', fontsize=13, fontweight='bold', pad=20)
        ax.grid(axis='y', alpha=0.3)

        def format_currency(x, p):
            if x >= 1e6:
                return f'{x / 1e6:.1f}M'
            elif x >= 1e3:
                return f'{x / 1e3:.0f}k'
            else:
                return f'{x:.0f}'

        ax.yaxis.set_major_formatter(plt.FuncFormatter(format_currency))

        max_cost_val = max(costs) if costs else 1

        for bar, cost in zip(bars, costs):
            if cost > 0.01:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2., max_cost_val * 1.05,
                        f'{cost:.2f} zł',
                        ha='center', va='bottom', fontsize=11, fontweight='bold', color='#333333')

        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _draw_cost_history_chart(self, kind, meter, hist, initial, tariff):
        if kind == "elec":
            frame = self.cost_chart_e_frame
        elif kind == "water":
            frame = self.cost_chart_w_frame
        else:
            frame = self.cost_chart_g_frame

        for widget in frame.winfo_children():
            widget.destroy()

        frame_w = frame.winfo_width()
        frame_h = frame.winfo_height()

        if frame_w < 200:
            frame_w = 600
        if frame_h < 200:
            frame_h = 300

        dpi = 100
        figsize_w = max(frame_w / dpi * 0.95, 4)
        figsize_h = max(frame_h / dpi * 0.95, 2.5)

        fig = Figure(figsize=(figsize_w, figsize_h), dpi=dpi)
        fig.patch.set_facecolor('white')

        ax = fig.add_subplot(111)

        costs_data = []
        labels_data = []

        prev_value = float(initial) if initial is not None else 0.0
        for i, r in enumerate(hist[-6:]):
            curr_value = float(r["value"])
            period_cost = (curr_value - prev_value) * tariff if tariff else 0
            if period_cost < 0:
                period_cost = 0
            costs_data.append(period_cost)
            ts_str = r["ts"]
            if len(ts_str) > 10:
                ts_str = ts_str[:10]
            labels_data.append(f'{period_cost:.2f}\n{ts_str}')
            prev_value = curr_value

        ax.plot(range(len(costs_data)), costs_data, marker='o', color='#1976D2', linewidth=2, markersize=8)
        ax.fill_between(range(len(costs_data)), costs_data, alpha=0.3, color='#1976D2')
        ax.set_xticks(range(len(labels_data)))
        ax.set_xticklabels(labels_data, fontsize=9)
        ax.set_ylabel('Koszt (zł)', fontsize=11, fontweight='bold')
        ax.set_title('Historia kosztów (ostatnie 6)', fontsize=13, fontweight='bold')
        ax.grid(True, alpha=0.3)

        fig.subplots_adjust(left=0.1, right=0.95, top=0.88, bottom=0.12)

        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def build_hist(self):
        frm = self.t_hist;
        pad = 16
        ttk.Label(frm, text="Wybierz licznik:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", padx=pad, pady=(pad, 8))
        self.h_sel_var = tk.StringVar()
        self.h_sel = ttk.Combobox(frm, textvariable=self.h_sel_var, state="readonly", width=48, font=('Segoe UI', 10))
        self.h_sel.pack(padx=pad, pady=(0, 12))
        cols = ("ts", "value")
        self.tbl_hist = ttk.Treeview(frm, columns=cols, show="headings", height=16)
        self.tbl_hist.heading("ts", text="DATA")
        self.tbl_hist.heading("value", text="STAN")
        for c, w in zip(cols, (400, 200)):
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
        opts = [f'{m["name"]} ({m["kind"]})' for m in meters]
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

        initial = m.get("initial_reading")
        if initial is not None:
            self.tbl_hist.insert("", "end", values=("Odczyt początkowy", f'{float(initial):.3f}'), tags=('initial',))

        for r in history_readings(m["id"]):
            self.tbl_hist.insert("", "end", values=(r["ts"], f'{float(r["value"]):.3f}'), tags=('reading', r["id"]))

    def remove_reading(self):
        sel = self.tbl_hist.selection()
        if not sel:
            messagebox.showinfo("Info", "Zaznacz wiersz do usunięcia.")
            return
        item = self.tbl_hist.item(sel[0])
        tags = item["tags"]

        if 'initial' in tags:
            messagebox.showwarning("Uwaga", "Nie można usunąć odczytu początkowego.")
            return

        rid = tags[1] if len(tags) > 1 else None
        if rid and messagebox.askyesno("Potwierdzenie", "Usunąć wybrany odczyt?"):
            delete_reading(rid)
            self.load_history_table()
            self.refresh_meters_table()

    def build_edit(self):
        frm = self.t_edit
        pad = 16

        top_frame = ttk.Frame(frm)
        top_frame.pack(fill="both", expand=True, padx=pad, pady=pad)

        ttk.Label(top_frame, text="Liczniki do edycji:", font=('Segoe UI', 11, 'bold')).pack(anchor="w", pady=(0, 8))

        cols = ("nazwa", "rodzaj", "taryfa")
        self.tbl_edit = ttk.Treeview(top_frame, columns=cols, show="headings", height=8)
        self.tbl_edit.heading("nazwa", text="NAZWA")
        self.tbl_edit.heading("rodzaj", text="RODZAJ")
        self.tbl_edit.heading("taryfa", text="TARYFA")
        for c, w in zip(cols, (200, 100, 200)):
            self.tbl_edit.column(c, width=w, anchor="center")

        scrollbar = ttk.Scrollbar(top_frame, orient="vertical", command=self.tbl_edit.yview)
        self.tbl_edit.configure(yscrollcommand=scrollbar.set)
        self.tbl_edit.pack(side="left", fill="both", expand=True, pady=(0, 12))
        scrollbar.pack(side="right", fill="y", padx=(4, 0), pady=(0, 12))

        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(pady=(0, 12))
        ttk.Button(btn_frame, text="✏️ Edytuj", command=self.edit_meter).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="🗑️ Usuń", command=self.delete_selected_meter).pack(side="left", padx=4)

        sep = ttk.Separator(frm, orient="horizontal")
        sep.pack(fill="x", padx=pad, pady=8)

        edit_form_frame = ttk.Frame(frm)
        edit_form_frame.pack(fill="both", padx=pad, pady=(0, pad))

        self.edit_form_visible = False
        self.edit_form_frame = edit_form_frame
        self._current_edited_meter = None

        ttk.Label(edit_form_frame, text="Edycja licznika:", font=('Segoe UI', 10, 'bold')).pack(anchor="w", pady=(0, 12))

        r1 = ttk.Frame(edit_form_frame)
        r1.pack(fill="x", pady=6)
        ttk.Label(r1, text="Nazwa:", width=15).pack(side="left")
        self.edit_name_var = tk.StringVar()
        ttk.Entry(r1, textvariable=self.edit_name_var, width=40).pack(side="left", padx=(0, 12))

        r2 = ttk.Frame(edit_form_frame)
        r2.pack(fill="x", pady=6)
        ttk.Label(r2, text="Rodzaj:", width=15).pack(side="left")
        self.edit_kind_var = tk.StringVar()
        self.edit_kind_combo = ttk.Combobox(r2, textvariable=self.edit_kind_var, state="readonly",
                                           values=["prąd", "woda", "gaz"], width=37)
        self.edit_kind_combo.pack(side="left", padx=(0, 12))

        r3 = ttk.Frame(edit_form_frame)
        r3.pack(fill="x", pady=6)
        ttk.Label(r3, text="Taryfa:", width=15).pack(side="left")
        self.edit_tariff_var = tk.StringVar()
        ttk.Entry(r3, textvariable=self.edit_tariff_var, width=40).pack(side="left", padx=(0, 12))

        btn_frame2 = ttk.Frame(edit_form_frame)
        btn_frame2.pack(pady=(12, 0))
        ttk.Button(btn_frame2, text="Zapisz", command=self.save_edited_meter).pack(side="left", padx=4)
        ttk.Button(btn_frame2, text="Anuluj", command=self.cancel_edit_meter).pack(side="left", padx=4)

        self.hide_edit_form()
        self.refresh_edit_table()

    def refresh_edit_table(self):
        for i in self.tbl_edit.get_children():
            self.tbl_edit.delete(i)

        self._meters_cache_edit = []
        for m in load_meters():
            self._meters_cache_edit.append(m)
            kind = m["kind"]
            if m.get("tariff") is not None:
                if kind == "prąd":
                    tariff_text = f'{float(m["tariff"]):.2f} zł/kWh'
                elif kind in ("woda", "gaz"):
                    tariff_text = f'{float(m["tariff"]):.2f} zł/m³'
                else:
                    tariff_text = f'{float(m["tariff"]):.2f}'
            else:
                tariff_text = ""

            self.tbl_edit.insert("", "end", values=(m["name"], m["kind"], tariff_text))

    def show_edit_form(self):
        self.edit_form_frame.pack(fill="both", padx=16, pady=(0, 16))
        self.edit_form_visible = True

    def hide_edit_form(self):
        self.edit_form_frame.pack_forget()
        self.edit_form_visible = False

    def edit_meter(self):
        sel = self.tbl_edit.selection()
        if not sel:
            messagebox.showinfo("Info", "Zaznacz licznik do edycji.")
            return

        item_index = self.tbl_edit.index(sel[0])
        meter = self._meters_cache_edit[item_index]

        self._current_edited_meter = meter
        self.edit_name_var.set(meter["name"])
        self.edit_kind_var.set(meter["kind"])
        self.edit_tariff_var.set(str(meter.get("tariff") or ""))
        self.show_edit_form()

    def save_edited_meter(self):
        if not self._current_edited_meter:
            return

        try:
            name = self.edit_name_var.get().strip()
            kind = self.edit_kind_var.get()
            tariff_str = self.edit_tariff_var.get().strip()

            if not name:
                messagebox.showerror("Błąd", "Podaj nazwę licznika.")
                return

            if tariff_str and not self._is_valid_number(tariff_str):
                messagebox.showerror("Błąd", "Proszę wpisać liczbę w taryfa")
                return

            update_meter(self._current_edited_meter["id"], name, kind, tariff_str, self._current_edited_meter.get("initial_reading"))
            messagebox.showinfo("OK", "Licznik zaktualizowany.")
            self.cancel_edit_meter()
            self.refresh_all()
        except Exception as e:
            error_msg = str(e)
            if "Error updating meter: " in error_msg:
                error_msg = error_msg.replace("Error updating meter: ", "")
            messagebox.showerror("Błąd", error_msg)

    def cancel_edit_meter(self):
        self._current_edited_meter = None
        self.edit_name_var.set("")
        self.edit_kind_var.set("")
        self.edit_tariff_var.set("")
        self.hide_edit_form()

    def delete_selected_meter(self):
        sel = self.tbl_edit.selection()
        if not sel:
            messagebox.showinfo("Info", "Zaznacz licznik do usunięcia.")
            return

        item_index = self.tbl_edit.index(sel[0])
        meter = self._meters_cache_edit[item_index]

        if messagebox.askyesno("Potwierdzenie",
                               f"Usunąć licznik '{meter['name']}'?\nWszystkie jego odczyty zostaną usunięte."):
            delete_meter(meter["id"])
            self.refresh_all()

    def build_chart(self):
        frm = self.t_chart
        pad = 16

        main_frame = ttk.Frame(frm)
        main_frame.pack(fill="both", expand=True, padx=pad, pady=pad)

        left_menu = ttk.Frame(main_frame, relief="sunken", borderwidth=1)
        left_menu.pack(side="left", fill="y", padx=(0, 12))

        ttk.Label(left_menu, text="Wybierz typ:", font=('Segoe UI', 10, 'bold'),
                  foreground="#1976D2").pack(anchor="w", padx=12, pady=(12, 8))

        self.chart_type_var = tk.StringVar(value="prąd")

        for kind_name, emoji in [("prąd", "⚡"), ("woda", "💧"), ("gaz", "🔥")]:
            btn = ttk.Button(left_menu, text=f"{emoji} {kind_name.upper()}",
                             command=lambda k=kind_name: self._switch_chart_meter_type(k))
            btn.pack(fill="x", padx=8, pady=4)

        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side="left", fill="both", expand=True)

        info_frame = ttk.Frame(right_panel)
        info_frame.pack(fill="x", padx=8, pady=(0, 12))

        ttk.Label(info_frame, text="Wybierz licznik:", font=('Segoe UI', 10)).pack(anchor="w", pady=(0, 4))

        top_combo_frame = ttk.Frame(info_frame)
        top_combo_frame.pack(fill="x")

        self.c_sel_var_e = tk.StringVar()
        self.c_sel_var_w = tk.StringVar()
        self.c_sel_var_g = tk.StringVar()

        self.c_sel_e = ttk.Combobox(top_combo_frame, textvariable=self.c_sel_var_e, state="readonly",
                                    width=40, font=('Segoe UI', 10))
        self.c_sel_w = ttk.Combobox(top_combo_frame, textvariable=self.c_sel_var_w, state="readonly",
                                    width=40, font=('Segoe UI', 10))
        self.c_sel_g = ttk.Combobox(top_combo_frame, textvariable=self.c_sel_var_g, state="readonly",
                                    width=40, font=('Segoe UI', 10))

        self.c_sel_e.bind("<<ComboboxSelected>>", lambda e: self.update_chart())
        self.c_sel_w.bind("<<ComboboxSelected>>", lambda e: self.update_chart())
        self.c_sel_g.bind("<<ComboboxSelected>>", lambda e: self.update_chart())

        btn_frame = ttk.Frame(right_panel)
        btn_frame.pack(padx=8, pady=(8, 12), fill="x")
        ttk.Button(btn_frame, text="📊 Porównanie", command=lambda: self._switch_chart_type("comparison")).pack(
            side="left", padx=4)
        ttk.Button(btn_frame, text="📈 Historia", command=lambda: self._switch_chart_type("history")).pack(side="left",
                                                                                                          padx=4)
        ttk.Button(btn_frame, text="🔄 Odśwież", command=self.update_chart).pack(side="left", padx=4)

        chart_frame_label = ttk.LabelFrame(right_panel, text="Wykres zużycia")
        chart_frame_label.pack(fill="both", expand=True, padx=8, pady=(0, 0))

        self.chart_e_frame = ttk.Frame(chart_frame_label)
        self.chart_w_frame = ttk.Frame(chart_frame_label)
        self.chart_g_frame = ttk.Frame(chart_frame_label)

        self._chart_type = "comparison"
        self.refresh_chart_e_combo()
        self.refresh_chart_w_combo()
        self.refresh_chart_g_combo()
        self._switch_chart_meter_type("prąd")

    def _switch_chart_type(self, chart_type):
        self._chart_type = chart_type
        self.update_chart()

    def _switch_chart_meter_type(self, kind):
        for frame in [self.chart_e_frame, self.chart_w_frame, self.chart_g_frame]:
            frame.pack_forget()
        for combo in [self.c_sel_e, self.c_sel_w, self.c_sel_g]:
            combo.pack_forget()

        self.chart_type_var.set(kind)

        if kind == "prąd":
            self.c_sel_e.pack(fill="x")
            self.chart_e_frame.pack(fill="both", expand=True)
            self.update_chart()
        elif kind == "woda":
            self.c_sel_w.pack(fill="x")
            self.chart_w_frame.pack(fill="both", expand=True)
            self.update_chart()
        else:
            self.c_sel_g.pack(fill="x")
            self.chart_g_frame.pack(fill="both", expand=True)
            self.update_chart()

    def refresh_chart_e_combo(self):
        elec = load_meters(kind="prąd")
        self._meters_cache_e_chart = elec
        opts = [f'{m["name"]}' for m in elec]
        self.c_sel_e["values"] = opts
        if opts:
            self.c_sel_e.current(len(opts) - 1)

    def refresh_chart_w_combo(self):
        water = load_meters(kind="woda")
        self._meters_cache_w_chart = water
        opts = [f'{m["name"]}' for m in water]
        self.c_sel_w["values"] = opts
        if opts:
            self.c_sel_w.current(len(opts) - 1)

    def refresh_chart_g_combo(self):
        gas = load_meters(kind="gaz")
        self._meters_cache_g_chart = gas
        opts = [f'{m["name"]}' for m in gas]
        self.c_sel_g["values"] = opts
        if opts:
            self.c_sel_g.current(len(opts) - 1)

    def update_chart(self):
        kind = self.chart_type_var.get()
        if kind == "prąd":
            idx = self.c_sel_e.current()
            cache = getattr(self, "_meters_cache_e_chart", [])
            frame = self.chart_e_frame
        elif kind == "woda":
            idx = self.c_sel_w.current()
            cache = getattr(self, "_meters_cache_w_chart", [])
            frame = self.chart_w_frame
        else:
            idx = self.c_sel_g.current()
            cache = getattr(self, "_meters_cache_g_chart", [])
            frame = self.chart_g_frame

        if idx < 0 or not cache:
            return

        m = cache[idx]

        for widget in frame.winfo_children():
            widget.destroy()

        hist = history_readings(m["id"])
        initial = m.get("initial_reading")
        total_readings = len(hist) + (1 if initial is not None else 0)

        if total_readings < 2:
            ttk.Label(frame, text="Potrzebne są co najmniej 2 odczyty do wyświetlenia wykresu.",
                      font=('Segoe UI', 10)).pack(padx=16, pady=16)
            return

        self.after(100, lambda: self._draw_chart_matplotlib(m, hist, frame))

    def _draw_chart_matplotlib(self, m, hist, frame):
        frame_w = frame.winfo_width()
        frame_h = frame.winfo_height()

        if frame_w < 200:
            frame_w = 1000
        if frame_h < 200:
            frame_h = 500

        dpi = 100
        figsize_w = max(frame_w / dpi * 0.95, 6)
        figsize_h = max(frame_h / dpi * 0.95, 4)

        fig = Figure(figsize=(figsize_w, figsize_h), dpi=dpi)
        fig.patch.set_facecolor('white')

        ax = fig.add_subplot(111)

        readings_data = []
        labels_data = []

        initial = m.get("initial_reading")
        if initial is not None:
            initial_val = float(initial)
            readings_data.append(initial_val)
            labels_data.append(f'{initial_val:.2f}\nPoczątkowy')

        for i, r in enumerate(hist[-6:]):
            value = float(r["value"])
            readings_data.append(value)
            ts_str = r["ts"]
            if len(ts_str) > 10:
                ts_str = ts_str[:10]
            labels_data.append(f'{value:.2f}\n{ts_str}')

        if self._chart_type == "comparison":
            colors_comparison = ['#FF6B6B', '#1976D2']
            if len(hist) >= 1:
                curr = float(hist[-1]["value"])

                if len(hist) == 1:
                    initial_val = float(initial) if initial is not None else 0
                    if initial_val == 0 or initial_val < 0.01:
                        bar_labels = ['Aktualny\nodczyt']
                        bar_values = [curr]
                        colors_comparison = ['#1976D2']
                        edgecolors_comp = ['#1565C0']
                    else:
                        bar_labels = ['Początkowy\nodczyt', 'Aktualny\nodczyt']
                        bar_values = [initial_val, curr]
                        colors_comparison = ['#FF6B6B', '#1976D2']
                        edgecolors_comp = ['#D32F2F', '#1565C0']
                else:
                    prev = float(hist[-2]["value"])
                    initial_val = prev
                    bar_labels = ['Poprzedni\nodczyt', 'Aktualny\nodczyt']
                    bar_values = [prev, curr]
                    colors_comparison = ['#FF6B6B', '#1976D2']
                    edgecolors_comp = ['#D32F2F', '#1565C0']

                bars = ax.bar(bar_labels, bar_values, color=colors_comparison, edgecolor=edgecolors_comp,
                              linewidth=2)
                ax.set_ylabel('Wartość [' + self._get_unit(m["kind"]) + ']', fontsize=11, fontweight='bold')
                ax.set_title('Porównanie zużycia', fontsize=13, fontweight='bold', pad=20)
                ax.grid(axis='y', alpha=0.3)

                max_val = max(bar_values)
                for i, (bar, v) in enumerate(zip(bars, bar_values)):
                    ax.text(bar.get_x() + bar.get_width() / 2., max_val * 1.05, f'{v:.2f}', ha='center', va='bottom',
                            fontsize=11, fontweight='bold')
        else:
            ax.plot(range(len(readings_data)), readings_data, marker='o', color='#1976D2', linewidth=2, markersize=8)
            ax.fill_between(range(len(readings_data)), readings_data, alpha=0.3, color='#1976D2')
            ax.set_xticks(range(len(labels_data)))
            ax.set_xticklabels(labels_data, fontsize=9)
            ax.set_ylabel('Wartość [' + self._get_unit(m["kind"]) + ']', fontsize=11, fontweight='bold')
            ax.set_title('Historia odczytów (ostatnie 6)', fontsize=13, fontweight='bold')
            ax.grid(True, alpha=0.3)

        fig.subplots_adjust(left=0.1, right=0.95, top=0.88, bottom=0.12)

        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _get_unit(self, kind):
        units = {
            "prąd": "kWh",
            "woda": "m³",
            "gaz": "m³"
        }
        return units.get(kind, "szt.")

    def refresh_all(self):
        self.refresh_meters_table()
        self.refresh_read_combo()
        self.refresh_e_combo()
        self.refresh_w_combo()
        self.refresh_g_combo()
        self.refresh_h_combo()
        self.refresh_edit_table()
        self.refresh_chart_e_combo()
        self.refresh_chart_w_combo()
        self.refresh_chart_g_combo()

        if self.cost_type_var.get() == "prąd":
            self.calc_cost_elec()
        elif self.cost_type_var.get() == "woda":
            self.calc_cost_water()
        else:
            self.calc_cost_gas()

        self.update_chart()


if __name__ == "__main__":
    app = App()
    app.mainloop()

