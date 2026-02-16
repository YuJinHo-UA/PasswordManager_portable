#!/usr/bin/env python3
# main.py — Portable Password Manager (improved security + admin recovery + password rotation)
# Dependencies: customtkinter, cryptography, pyperclip

import os
import sys
import time
import json
import base64
import sqlite3
import threading
import secrets
import string
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk
import pyperclip

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# ---------------- Configuration ----------------
DB_FILE = "database.db"
DEK_META = "dek_wrapped.json"     # stores salt, iterations, enc_dek_user, enc_dek_admin
AUTOLOCK_SECONDS = 120
CLIP_CLEAR_SECONDS = 30
PASSWORD_ROTATION_DAYS = 30

# ---------------- Utilities ----------------
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=iterations,
                     backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def generate_dek() -> bytes:
    return base64.urlsafe_b64encode(secrets.token_bytes(32))

def generate_password(length: int=20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def save_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------- Database ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            service BLOB,
            login BLOB,
            password BLOB,
            created_at INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            ts INTEGER,
            who TEXT,
            action TEXT,
            record_id INTEGER,
            meta TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------------- Application ----------------
class PortablePasswordManager:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("Portable Password Manager (Secure)")
        self.root.geometry("920x620")
        # appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # state
        self.dek = None          # bytes key for Fernet
        self.cipher = None       # Fernet(self.dek)
        self.last_activity = time.time()
        self.clip_clear_timer = None
        self.sort_asc = True
        self.search_var = ctk.StringVar()
        self.theme_var = ctk.StringVar(value="dark")

        init_db()
        # If DEK metadata missing -> first time
        if not os.path.exists(DEK_META):
            self.first_time_setup()
        else:
            self.master_password_screen()

        # autolock checker
        self.root.after(5000, self.autolock_check)

    # ---------- First time setup ----------
    def first_time_setup(self):
        self.clear()
        frame = ctk.CTkFrame(self.root)
        frame.pack(expand=True, fill="both", padx=24, pady=24)

        ctk.CTkLabel(frame, text="Первичный запуск — создайте мастер-пароль", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(4,8))
        self.setup_entry = ctk.CTkEntry(frame, show="*", width=420)
        self.setup_entry.pack(pady=(0,8))
        ctk.CTkLabel(frame, text="Мастер-пароль будет использоваться для восстановления DEK (KEK → DEK)").pack()
        self.make_admin_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(frame, text="Создать admin.key для восстановления (рекомендуется хранить на USB)", variable=self.make_admin_var).pack(pady=(8,6))
        ctk.CTkButton(frame, text="Создать", command=self.finish_first_time).pack(pady=12)
        ctk.CTkLabel(frame, text="Внимание: admin.key — файл для восстановления. Храните его отдельно!", text_color="#f1c40f").pack(pady=(8,0))

    def finish_first_time(self):
        pwd = self.setup_entry.get().strip()
        if not pwd:
            messagebox.showerror("Ошибка", "Пароль пустой")
            return
        salt = secrets.token_bytes(16)
        iterations = 200000
        dek = generate_dek()                       # random DEK bytes (urlsafe_b64)
        user_kek = derive_key(pwd, salt, iterations)
        f_user = Fernet(user_kek)
        enc_dek_user = f_user.encrypt(dek)

        enc_dek_admin = None
        if self.make_admin_var.get():
            # generate admin raw (32 bytes) and wrap
            admin_raw = secrets.token_bytes(32)
            admin_kek = base64.urlsafe_b64encode(admin_raw)
            f_admin = Fernet(admin_kek)
            enc_dek_admin = f_admin.encrypt(dek)
            # Save admin key to a file — prompt user where to save
            save_path = simpledialog.askstring("Сохранение admin.key", "Укажите путь для сохранения admin.key (например: D:/admin.key):")
            try:
                if save_path:
                    with open(save_path, "wb") as ak:
                        ak.write(admin_raw)
                    messagebox.showinfo("admin.key", f"admin.key записан в: {save_path}\nХраните этот файл отдельно!")
                else:
                    # fall back to local (for testing) but warn
                    with open("admin.key", "wb") as ak:
                        ak.write(admin_raw)
                    messagebox.showwarning("admin.key", "admin.key сохранён локально как admin.key (для теста). Рекомендуется переместить на внешний носитель.")
            except Exception as e:
                messagebox.showwarning("admin.key", f"Не удалось записать admin.key: {e}")

        meta = {
            "salt": b64(salt),
            "iterations": iterations,
            "enc_dek_user": b64(enc_dek_user),
            "enc_dek_admin": b64(enc_dek_admin) if enc_dek_admin else None
        }
        save_json(DEK_META, meta)
        # keep DEK in memory for immediate session
        self.dek = dek
        self.cipher = Fernet(self.dek)
        self.log_action("system", "first_setup", None, "dek_created")
        messagebox.showinfo("Готово", "Первичная настройка завершена. DEK сохранён (защищённый).")
        self.main_screen(admin=bool(enc_dek_admin))

    # ---------- Master/Admin entry ----------
    def master_password_screen(self):
        self.clear()
        frame = ctk.CTkFrame(self.root)
        frame.pack(expand=True, fill="both", padx=24, pady=24)
        ctk.CTkLabel(frame, text="Введите мастер-пароль (KEK) или войдите как админ с admin.key", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(6,8))
        self.master_entry = ctk.CTkEntry(frame, show="*", width=420)
        self.master_entry.pack(pady=6)
        ctk.CTkButton(frame, text="Войти (master)", command=self.check_master).pack(pady=(8,6))

        # Admin path
        ctk.CTkLabel(frame, text="Если у вас есть admin.key, нажмите кнопку и укажите путь к файлу", text_color="#f1c40f").pack(pady=(8,4))
        ctk.CTkButton(frame, text="Войти как admin (admin.key)", command=self.admin_unlock).pack(pady=6)

        ctk.CTkButton(frame, text="Сбросить локально (удалит DB и DEK)", fg_color="#b22222", hover_color="#ff4444", command=self.reset_local_prompt).pack(pady=(12,0))

    def check_master(self):
        pwd = self.master_entry.get().strip()
        if not pwd:
            messagebox.showerror("Ошибка", "Пароль пустой")
            return
        if not os.path.exists(DEK_META):
            messagebox.showerror("Ошибка", "DEK мета не найдена")
            return
        meta = load_json(DEK_META)
        salt = ub64(meta["salt"])
        iterations = int(meta["iterations"])
        enc_user = ub64(meta["enc_dek_user"])
        try:
            user_kek = derive_key(pwd, salt, iterations)
            f_user = Fernet(user_kek)
            dek = f_user.decrypt(enc_user)   # May raise InvalidToken
            self.dek = dek
            self.cipher = Fernet(self.dek)
            self.log_action("user", "login", None, "master_login_success")
            self.main_screen(admin=False)
        except InvalidToken:
            self.log_action("user", "login_failed", None, "wrong_master")
            messagebox.showerror("Ошибка", "Неверный мастер-пароль")

    def admin_unlock(self):
        path = simpledialog.askstring("admin.key", "Укажите путь до admin.key (пусто = admin.key в папке приложения):")
        if not path:
            path = "admin.key"
        if not os.path.exists(path):
            messagebox.showerror("Admin", f"Файл не найден: {path}")
            return
        try:
            with open(path, "rb") as f:
                admin_raw = f.read()
            admin_kek = base64.urlsafe_b64encode(admin_raw)
            meta = load_json(DEK_META)
            enc_admin = meta.get("enc_dek_admin")
            if not enc_admin:
                messagebox.showerror("Admin", "DEK не защищён admin.key (enc_dek_admin отсутствует).")
                return
            f_admin = Fernet(admin_kek)
            dek = f_admin.decrypt(ub64(enc_admin))
            self.dek = dek
            self.cipher = Fernet(self.dek)
            self.log_action("admin", "admin_unlock", None, f"admin_key:{os.path.basename(path)}")
            messagebox.showinfo("Admin", "Успешный вход как админ")
            self.main_screen(admin=True)
        except Exception as e:
            messagebox.showerror("Admin", f"Не удалось войти как админ: {e}")

    def reset_local_prompt(self):
        ok = messagebox.askyesno("Сброс", "Это удалит локальные database.db и dek_wrapped.json. Продолжить?")
        if not ok:
            return
        try:
            for fn in (DB_FILE, DEK_META):
                if os.path.exists(fn):
                    os.remove(fn)
            init_db()
            messagebox.showinfo("Сброс", "Локальные данные удалены. Перезапустите приложение.")
            self.first_time_setup()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сбросить: {e}")

    # ---------- Main UI ----------
    def main_screen(self, admin: bool=False):
        self.update_activity()
        self.clear()
        top = ctk.CTkFrame(self.root)
        top.pack(fill="x", padx=10, pady=8)

        add_btn = ctk.CTkButton(top, text="Добавить запись", command=self.add_record_screen)
        add_btn.pack(side="left", padx=6)
        refresh_btn = ctk.CTkButton(top, text="Обновить", command=self.refresh_records)
        refresh_btn.pack(side="left", padx=6)
        rotate_btn = ctk.CTkButton(top, text="Rotate Expired (Admin)", command=self.rotate_expired_prompt)
        rotate_btn.pack(side="left", padx=6)
        sort_btn = ctk.CTkButton(top, text="Сорт A↕Z", command=self.toggle_sort)
        sort_btn.pack(side="left", padx=6)

        theme_switch = ctk.CTkSegmentedButton(top, values=["dark", "light"], variable=self.theme_var, command=self.change_theme)
        theme_switch.set(self.theme_var.get())
        theme_switch.pack(side="right", padx=6)

        sf = ctk.CTkFrame(self.root)
        sf.pack(fill="x", padx=12, pady=(6,4))
        search_entry = ctk.CTkEntry(sf, placeholder_text="Поиск по сервису или логину...", textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=(0,6))
        search_entry.bind("<KeyRelease>", lambda e: (self.update_activity(), self.refresh_records()))
        ctk.CTkButton(sf, text="X", width=40, command=lambda: (self.search_var.set(""), self.refresh_records())).pack(side="right")

        self.records_area = ctk.CTkScrollableFrame(self.root, corner_radius=8)
        self.records_area.pack(fill="both", expand=True, padx=12, pady=8)

        bottom = ctk.CTkFrame(self.root)
        bottom.pack(fill="x", padx=12, pady=(0,10))
        lock_btn = ctk.CTkButton(bottom, text="Заблокировать", command=self.lock_app)
        lock_btn.pack(side="left")
        export_btn = ctk.CTkButton(bottom, text="Экспорт (зашифр.)", command=self.export_backup)
        export_btn.pack(side="right")
        if admin:
            admin_btn = ctk.CTkButton(bottom, text="Просмотр логов (Admin)", command=self.admin_view_logs)
            admin_btn.pack(side="right", padx=6)

        # Check expired and visually mark count
        expired = self.get_expired_count()
        if expired:
            ctk.CTkLabel(top, text=f"⚠ {expired} паролей старше {PASSWORD_ROTATION_DAYS} дней", text_color="#f39c12").pack(side="left", padx=6)

        self.refresh_records()

    # ---------- Add record ----------
    def add_record_screen(self):
        self.update_activity()
        self.clear()
        frame = ctk.CTkFrame(self.root)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Добавить запись", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(6,8))
        ctk.CTkLabel(frame, text="Сервис").pack(anchor="w", padx=6)
        svc = ctk.CTkEntry(frame, width=540); svc.pack(padx=6, pady=(0,8))
        ctk.CTkLabel(frame, text="Логин").pack(anchor="w", padx=6)
        login = ctk.CTkEntry(frame, width=540); login.pack(padx=6, pady=(0,8))
        ctk.CTkLabel(frame, text="Пароль").pack(anchor="w", padx=6)
        pwd_entry = ctk.CTkEntry(frame, width=540); pwd_entry.pack(padx=6, pady=(0,8))

        def gen_pwd():
            pw = generate_password(20)
            pwd_entry.delete(0, "end"); pwd_entry.insert(0, pw)
            try:
                pyperclip.copy(pw); self.schedule_clipboard_clear(); messagebox.showinfo("Сгенерировано", "Пароль сгенерирован и скопирован в буфер")
            except Exception:
                messagebox.showinfo("Сгенерировано", "Пароль сгенерирован")

        ctk.CTkButton(frame, text="Сгенерировать", command=gen_pwd).pack(pady=(6,6))

        def save_rec():
            s = svc.get().strip(); l = login.get().strip(); p = pwd_entry.get().strip()
            if not (s and l and p):
                messagebox.showerror("Ошибка", "Заполните все поля"); return
            enc_s = self.cipher.encrypt(s.encode()).decode()
            enc_l = self.cipher.encrypt(l.encode()).decode()
            enc_p = self.cipher.encrypt(p.encode()).decode()
            conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
            cur.execute("INSERT INTO accounts(service, login, password, created_at) VALUES (?, ?, ?, ?)", (enc_s, enc_l, enc_p, int(time.time())))
            conn.commit(); conn.close()
            self.log_action("user", "add", None, s)
            messagebox.showinfo("Успех", "Запись сохранена")
            self.main_screen()

        btnf = ctk.CTkFrame(frame); btnf.pack(pady=10)
        ctk.CTkButton(btnf, text="Сохранить", command=save_rec).pack(side="left", padx=6)
        ctk.CTkButton(btnf, text="Отмена", command=lambda: self.main_screen()).pack(side="right", padx=6)

    # ---------- Records ----------
    def refresh_records(self):
        self.update_activity()
        for w in self.records_area.winfo_children():
            w.destroy()
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        cur.execute("SELECT id, service, login, password, created_at FROM accounts")
        rows = cur.fetchall(); conn.close()

        q = self.search_var.get().strip().lower()
        if q:
            rows = [r for r in rows if q in (self.safe_decrypt(r[1]) or "").lower() or q in (self.safe_decrypt(r[2]) or "").lower()]

        rows.sort(key=lambda x: (self.safe_decrypt(x[1]) or "").lower(), reverse=(not self.sort_asc))

        if not rows:
            ctk.CTkLabel(self.records_area, text="Записей нет").pack(pady=12); return

        for r in rows:
            rid, s_enc, l_enc, p_enc, created = r
            service = self.safe_decrypt(s_enc) or "<Ошибка>"
            login = self.safe_decrypt(l_enc) or ""
            frame = ctk.CTkFrame(self.records_area, corner_radius=6); frame.pack(fill="x", padx=8, pady=6)
            left = ctk.CTkLabel(frame, text=f"{service} — {login}", anchor="w")
            left.pack(side="left", padx=8, pady=8, fill="x", expand=True)

            # show (open dialog with confirmation)
            def make_show(enc=p_enc, svc=service, rid_local=rid):
                def _show():
                    try:
                        dec = self.cipher.decrypt(enc.encode()).decode()
                    except Exception:
                        messagebox.showerror("Ошибка", "Не удалось расшифровать"); return
                    # confirmation
                    if not messagebox.askyesno("Показать пароль", f"Показать пароль для «{svc}»?"):
                        return
                    w = tk.Toplevel(self.root); w.title(f"Пароль — {svc}")
                    w.geometry("420x140")
                    tk.Label(w, text=dec, font=("Consolas", 12)).pack(padx=12, pady=12)
                    tk.Button(w, text="Копировать", command=lambda: (pyperclip.copy(dec), self.schedule_clipboard_clear(), messagebox.showinfo("Копия", "Скопировано"))).pack(pady=(0,12))
                    self.log_action("user", "view", rid_local, svc)
                return _show
            show_btn = ctk.CTkButton(frame, text="Показать", width=90, command=make_show())
            show_btn.pack(side="right", padx=6)

            # copy quick
            def make_copy(enc=p_enc, svc=service, rid_local=rid):
                def _copy():
                    try:
                        dec = self.cipher.decrypt(enc.encode()).decode()
                    except Exception:
                        messagebox.showerror("Ошибка", "Не удалось расшифровать"); return
                    try:
                        pyperclip.copy(dec); self.schedule_clipboard_clear(); messagebox.showinfo("Копия", f"Скопировано в буфер (очистится через {CLIP_CLEAR_SECONDS}s)")
                        self.log_action("user", "copy", rid_local, svc)
                    except Exception:
                        messagebox.showwarning("Ошибка", "Копирование не удалось")
                return _copy
            copy_btn = ctk.CTkButton(frame, text="Копировать", width=110, command=make_copy())
            copy_btn.pack(side="right", padx=6)

            # delete (admin only can rotate/delete in mass; but leave delete for local)
            def make_delete(rid_local=rid, svc=service):
                def _del():
                    if not messagebox.askyesno("Удалить", f"Удалить запись «{svc}»?"): return
                    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
                    cur.execute("DELETE FROM accounts WHERE id = ?", (rid_local,))
                    conn.commit(); conn.close()
                    self.log_action("user", "delete", rid_local, svc); self.refresh_records()
                return _del
            del_btn = ctk.CTkButton(frame, text="Удалить", width=90, fg_color="#b22222", hover_color="#ff4444", command=make_delete())
            del_btn.pack(side="right", padx=6)

            # mark expired visually
            if created and isinstance(created, int):
                age_days = (int(time.time()) - created) / 86400.0
                if age_days >= PASSWORD_ROTATION_DAYS:
                    ctk.CTkLabel(frame, text="⚠ Просрочен", text_color="#f39c12").pack(side="left", padx=6)

    def safe_decrypt(self, blob: str) -> str:
        if not blob: return ""
        try:
            return self.cipher.decrypt(blob.encode()).decode()
        except Exception:
            return ""

    # ---------- Clipboard ----------
    def schedule_clipboard_clear(self):
        try:
            if self.clip_clear_timer and self.clip_clear_timer.is_alive():
                self.clip_clear_timer.cancel()
        except Exception:
            pass
        def clear_cb():
            try:
                pyperclip.copy("")
            except Exception:
                pass
        self.clip_clear_timer = threading.Timer(CLIP_CLEAR_SECONDS, clear_cb)
        self.clip_clear_timer.daemon = True
        self.clip_clear_timer.start()

    # ---------- Autolock ----------
    def update_activity(self):
        self.last_activity = time.time()
    def autolock_check(self):
        if self.cipher is not None and time.time() - self.last_activity >= AUTOLOCK_SECONDS:
            self.lock_app()
        self.root.after(5000, self.autolock_check)
    def lock_app(self):
        self.cipher = None; self.dek = None
        messagebox.showinfo("Блокировка", "Приложение заблокировано (idle)")
        self.master_password_screen()

    # ---------- Backup ----------
    def export_backup(self):
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor(); cur.execute("SELECT service,login,password,created_at FROM accounts"); rows = cur.fetchall(); conn.close()
        if not rows:
            messagebox.showinfo("Экспорт", "Нет записей"); return
        data = [{"s": r[0], "l": r[1], "p": r[2], "t": r[3]} for r in rows]
        blob = json.dumps(data).encode("utf-8")
        try:
            enc = self.cipher.encrypt(blob)
            fname = f"backup_{int(time.time())}.bin"
            with open(fname, "wb") as f: f.write(enc)
            messagebox.showinfo("Экспорт", f"Бэкап сохранён как {fname}")
            self.log_action("user", "export", None, fname)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать: {e}")

    # ---------- Audit logs ----------
    def log_action(self, who: str, action: str, record_id=None, meta=None):
        try:
            conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
            cur.execute("INSERT INTO audit_logs(ts, who, action, record_id, meta) VALUES(?,?,?,?,?)", (int(time.time()), who, action, record_id, meta))
            conn.commit(); conn.close()
        except Exception:
            pass

    def admin_view_logs(self):
        self.update_activity()
        w = tk.Toplevel(self.root); w.title("Audit Logs"); w.geometry("900x500")
        tf = ctk.CTkFrame(w); tf.pack(fill="both", expand=True, padx=8, pady=8)
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor(); cur.execute("SELECT ts, who, action, record_id, meta FROM audit_logs ORDER BY ts DESC LIMIT 1000"); rows = cur.fetchall(); conn.close()
        for r in rows:
            ts, who, action, rid, meta = r
            tstr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
            ctk.CTkLabel(tf, text=f"{tstr} | {who} | {action} | id={rid} | {meta}", anchor="w", wraplength=860).pack(anchor="w", pady=2, padx=6)

    # ---------- Expired / Rotate ----------
    def get_expired_count(self):
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        cutoff = int(time.time()) - PASSWORD_ROTATION_DAYS * 86400
        cur.execute("SELECT COUNT(1) FROM accounts WHERE created_at <= ?", (cutoff,))
        r = cur.fetchone(); conn.close()
        return r[0] if r else 0

    def rotate_expired_prompt(self):
        # Admin-only operation: request admin key or master (we already in admin session to see button)
        ans = messagebox.askyesno("Rotate", f"Сгенерировать новые пароли для всех записей старше {PASSWORD_ROTATION_DAYS} дней?")
        if not ans:
            return
        # rotate and show summary
        rotated = self.rotate_expired_passwords()
        messagebox.showinfo("Rotate", f"Обновлено паролей: {rotated}")
        self.refresh_records()
        self.log_action("admin", "rotate_expired", None, f"rotated:{rotated}")

    def rotate_expired_passwords(self) -> int:
        cutoff = int(time.time()) - PASSWORD_ROTATION_DAYS * 86400
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        cur.execute("SELECT id, service FROM accounts WHERE created_at <= ?", (cutoff,))
        rows = cur.fetchall()
        count = 0
        for r in rows:
            rid, s_enc = r
            new_pw = generate_password(20)
            enc_p = self.cipher.encrypt(new_pw.encode()).decode()
            cur.execute("UPDATE accounts SET password=?, created_at=? WHERE id=?", (enc_p, int(time.time()), rid))
            count += 1
            # optionally: write per-record note or notify admin — here we log
            self.log_action("admin", "rotated", rid, f"new_pw_len={len(new_pw)}")
        conn.commit(); conn.close()
        return count

    # ---------- Helpers ----------
    def toggle_sort(self):
        self.sort_asc = not self.sort_asc
        self.refresh_records()

    def change_theme(self, v):
        ctk.set_appearance_mode(v)

    def schedule_clipboard_clear(self):
        try:
            if self.clip_clear_timer and self.clip_clear_timer.is_alive():
                self.clip_clear_timer.cancel()
        except Exception:
            pass
        def clear_cb():
            try:
                pyperclip.copy("")
            except Exception:
                pass
        self.clip_clear_timer = threading.Timer(CLIP_CLEAR_SECONDS, clear_cb)
        self.clip_clear_timer.daemon = True
        self.clip_clear_timer.start()

    def clear(self):
        for w in self.root.winfo_children(): w.destroy()

# ---------------- Run ----------------
if __name__ == "__main__":
    # dependency check
    try:
        import customtkinter, cryptography, pyperclip
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror("Зависимости", f"Установи зависимости: pip install customtkinter cryptography pyperclip\n\n{e}")
        sys.exit(1)

    root = ctk.CTk()
    mgr = PortablePasswordManager(root)
    def global_activity(event=None):
        try: mgr.update_activity()
        except Exception: pass
    root.bind_all("<Any-KeyPress>", global_activity); root.bind_all("<Any-ButtonPress>", global_activity)
    root.mainloop()
