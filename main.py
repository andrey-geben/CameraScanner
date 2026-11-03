# Главный файл с GUI
# main.py
import argparse
import ctypes
import ipaddress
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import sv_ttk

try:
    import darkdetect
    _DARKDETECT_OK = True
except ImportError:
    _DARKDETECT_OK = False
    print("[theme] darkdetect не найден — используется тема 'light' по умолчанию")

from snmp_scanner import snmp_get
from wsdiscovery_scanner import discover_onvif
from sadp_scanner import discover_hikvision_sadp
from dahua_scanner import discover_dahua
from exporter import export_to_csv


# ------------------------------------------------------------------ constants
APP_NAME = "CameraScanner"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Andrew Geben"
APP_COPYRIGHT = f"© 2026 {APP_AUTHOR}. Все права принадлежат автору."
APP_DESCRIPTION = (
    "Утилита активного поиска IP-камер в локальной сети.\n"
    "Поддерживаемые протоколы: SNMP (v1/v2c/v3), ONVIF WS-Discovery, "
    "SADP (Hikvision), Dahua/Amcrest Discovery."
)
APP_LICENSE = "Распространяется по лицензии MIT."


# --------------------------------------------------------------------- helpers
def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)


def validate_ico(path: str) -> tuple[bool, str]:
    if not os.path.isfile(path):
        return False, f"Файл не найден: {path}"
    try:
        with open(path, "rb") as f:
            header = f.read(6)
        if len(header) < 6:
            return False, "Файл слишком короткий для .ico"
        if header[:4] not in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
            return False, "Не является .ico (нет сигнатуры 00 00 01 00)"
        count = int.from_bytes(header[4:6], "little")
        if count == 0:
            return False, ".ico не содержит изображений"
        return True, f"OK, {count} размер(ов)"
    except Exception as exc:
        return False, f"Ошибка чтения: {exc}"


def set_window_icon(root: tk.Tk) -> None:
    ico_path = resource_path("assets/app.ico")
    ok, info = validate_ico(ico_path)
    print(f"[icon] {ico_path} — {info}")
    if not ok:
        print("[icon] Иконка окна НЕ установлена.")
        return
    try:
        root.iconbitmap(default=ico_path)
        print("[icon] iconbitmap(default=...) — OK")
    except Exception as exc:
        print(f"[icon] iconbitmap(default=...) failed: {exc}")
        try:
            root.wm_iconbitmap(ico_path)
            print("[icon] wm_iconbitmap() — OK")
        except Exception as exc2:
            print(f"[icon] wm_iconbitmap() failed: {exc2}")


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False


def relaunch_as_admin(extra_args: list[str]) -> bool:
    if getattr(sys, "frozen", False):
        executable, args = sys.executable, ["--elevated"] + extra_args
    else:
        executable, args = sys.executable, [sys.argv[0], "--elevated"] + extra_args
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, " ".join(args), None, 1
    )
    return result > 32


# ---------------------------------------------------------- theme helpers
def apply_theme_to_titlebar(root: tk.Tk) -> None:
    try:
        import pywinstyles
    except ImportError:
        return
    if sys.platform != "win32":
        return
    version = sys.getwindowsversion()
    if version.major == 10 and version.build >= 22000:
        pywinstyles.change_header_color(
            root, "#1c1c1c" if sv_ttk.get_theme() == "dark" else "#fafafa"
        )
    elif version.major == 10:
        pywinstyles.apply_style(
            root, "dark" if sv_ttk.get_theme() == "dark" else "normal"
        )
        root.wm_attributes("-alpha", 0.99)
        root.wm_attributes("-alpha", 1)


# ---------------------------------------------------------------------- GUI
class CameraScannerApp:
    def __init__(self, root: tk.Tk, elevated: bool = False, restore: dict | None = None):
        self.root = root
        self.root.title(f"{APP_NAME} — IP Camera Discovery")
        self.root.geometry("1100x620")
        self.results: list[dict] = []
        self.elevated = elevated
        self.stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None
        restore = restore or {}

        # --- Применяем тему ---
        try:
            sv_ttk.set_theme(darkdetect.theme() if _DARKDETECT_OK and darkdetect.theme() else "light")
        except Exception:
            sv_ttk.set_theme("light")
        apply_theme_to_titlebar(self.root)

        self._build_menu()

        # ---------------------- Верхняя панель ввода ----------------------
        input_frame = ttk.Frame(root)
        input_frame.pack(pady=5, padx=5, fill="x")

        ttk.Label(input_frame, text="Подсеть (CIDR):").pack(side="left")
        self.subnet_entry = ttk.Entry(input_frame, width=20)
        self.subnet_entry.insert(0, restore.get("subnet", "192.168.1.0/24"))
        self.subnet_entry.pack(side="left", padx=5)

        ttk.Label(input_frame, text="SNMP Community:").pack(side="left")
        self.community_entry = ttk.Entry(input_frame, width=15)
        self.community_entry.insert(0, restore.get("community", "public"))
        self.community_entry.pack(side="left", padx=5)

        ttk.Label(input_frame, text="SNMP Version:").pack(side="left")
        self.snmp_version = ttk.Combobox(input_frame, values=["v1", "v2c", "v3"], width=5)
        self.snmp_version.set(restore.get("snmp_version", "v2c"))
        self.snmp_version.pack(side="left", padx=5)

        # ---------------------- Режим / протоколы ----------------------
        proto_frame = ttk.Frame(root)
        proto_frame.pack(pady=5, padx=5, fill="x")

        self.auto_discovery = tk.BooleanVar(value=restore.get("auto", False))
        self.auto_cb = ttk.Checkbutton(
            proto_frame, text="Автообнаружение (без подсети)",
            variable=self.auto_discovery, command=self.on_auto_toggle,
        )
        self.auto_cb.pack(side="left", padx=5)

        ttk.Separator(proto_frame, orient="vertical").pack(side="left", fill="y", padx=10)

        self.use_snmp = tk.BooleanVar(value=restore.get("snmp", True))
        self.use_onvif = tk.BooleanVar(value=restore.get("onvif", True))
        self.use_sadp = tk.BooleanVar(value=restore.get("sadp", False))
        self.use_dahua = tk.BooleanVar(value=restore.get("dahua", True))

        self.snmp_cb = ttk.Checkbutton(proto_frame, text="SNMP", variable=self.use_snmp)
        self.snmp_cb.pack(side="left", padx=5)
        ttk.Checkbutton(proto_frame, text="ONVIF", variable=self.use_onvif).pack(side="left", padx=5)
        self.sadp_cb = ttk.Checkbutton(
            proto_frame,
            text="SADP (Hikvision) — требует прав администратора",
            variable=self.use_sadp, command=self.on_sadp_toggle,
        )
        self.sadp_cb.pack(side="left", padx=5)
        ttk.Checkbutton(proto_frame, text="Dahua/Amcrest", variable=self.use_dahua).pack(side="left", padx=5)

        if self.elevated or is_admin():
            self.use_sadp.set(True)

        # ---------------------- Кнопки сканирования / стоп ----------------------
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=5)

        self.scan_btn = ttk.Button(btn_frame, text="Сканировать", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(
            btn_frame, text="Стоп", command=self.stop_scan, state="disabled",
        )
        self.stop_btn.pack(side="left", padx=5)

        # ---------------------- Таблица ----------------------
        columns = ("ip", "protocol", "info")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("ip", text="IP-адрес")
        self.tree.heading("protocol", text="Протокол")
        self.tree.heading("info", text="Информация")
        self.tree.column("ip", width=140, anchor="w")
        self.tree.column("protocol", width=100, anchor="w")
        self.tree.column("info", width=800, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

        # ---------------------- Нижняя панель ----------------------
        bottom = ttk.Frame(root)
        bottom.pack(fill="x", padx=5, pady=5)

        ttk.Button(bottom, text="Экспорт в CSV", command=self.export_csv).pack(side="left")

        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

        style = ttk.Style()
        style.configure("Footer.TLabel", foreground="#888888")
        self.copyright_label = ttk.Label(
            bottom,
            text=APP_COPYRIGHT,
            anchor="center",
            style="Footer.TLabel",
        )
        self.copyright_label.pack(side="left", expand=True, fill="x", padx=10)

        self.on_auto_toggle()

        if self.elevated and restore.get("autostart", True):
            self.root.after(300, self.start_scan)

    # --------------------------------------------------------------- меню
    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Экспорт в CSV…", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.destroy)
        menubar.add_cascade(label="Файл", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        self.theme_var = tk.StringVar(value=sv_ttk.get_theme())
        view_menu.add_radiobutton(
            label="Светлая тема", variable=self.theme_var, value="light",
            command=lambda: self._set_theme("light"),
        )
        view_menu.add_radiobutton(
            label="Тёмная тема", variable=self.theme_var, value="dark",
            command=lambda: self._set_theme("dark"),
        )
        menubar.add_cascade(label="Вид", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.root.config(menu=menubar)

    def _set_theme(self, theme: str):
        sv_ttk.set_theme(theme)
        self.theme_var.set(theme)
        apply_theme_to_titlebar(self.root)
        style = ttk.Style()
        style.configure(
            "Footer.TLabel",
            foreground="#888888" if theme == "dark" else "#666666",
        )

    # --------------------------------------------------------------- About
    def show_about(self):
        win = tk.Toplevel(self.root)
        win.title(f"О программе {APP_NAME}")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)
        try:
            win.iconbitmap(default=resource_path("assets/app.ico"))
        except Exception:
            pass

        frame = ttk.Frame(win, padding=15)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(frame, text=f"Версия {APP_VERSION}", foreground="#555").pack(anchor="w", pady=(0, 10))
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=5)
        ttk.Label(frame, text=APP_DESCRIPTION, justify="left").pack(anchor="w", pady=(5, 10))

        info = ttk.Frame(frame)
        info.pack(fill="x", pady=(0, 10))
        ttk.Label(info, text="Автор:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(info, text=APP_AUTHOR).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(info, text="Лицензия:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w")
        ttk.Label(info, text=APP_LICENSE).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(info, text="Python:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w")
        ttk.Label(info, text=sys.version.split()[0]).grid(row=2, column=1, sticky="w", padx=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=5)
        ttk.Label(frame, text=APP_COPYRIGHT, foreground="#666").pack(anchor="w", pady=(5, 10))
        ttk.Button(frame, text="OK", command=win.destroy).pack(anchor="e")

        win.update_idletasks()
        px, py = self.root.winfo_rootx(), self.root.winfo_rooty()
        pw, ph = self.root.winfo_width(), self.root.winfo_height()
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")

    # -------------------------------------------------------------- режимы
    def on_auto_toggle(self):
        if self.auto_discovery.get():
            self.subnet_entry.config(state="disabled")
            self.community_entry.config(state="disabled")
            self.snmp_version.config(state="disabled")
            self.use_snmp.set(False)
            self.snmp_cb.config(state="disabled")
        else:
            self.subnet_entry.config(state="normal")
            self.community_entry.config(state="normal")
            self.snmp_version.config(state="normal")
            self.snmp_cb.config(state="normal")
            self.use_snmp.set(True)

    # ------------------------------------------------------------------ UAC
    def on_sadp_toggle(self):
        if not self.use_sadp.get():
            return
        if is_admin():
            return
        answer = messagebox.askyesno(
            "Требуются права администратора",
            "Для сканирования SADP (Hikvision) необходимы права администратора.\n\n"
            "Перезапустить приложение с повышением прав?",
            parent=self.root,
        )
        if answer:
            extra = [
                "--subnet", self.subnet_entry.get(),
                "--community", self.community_entry.get(),
                "--snmp-version", self.snmp_version.get(),
                "--auto", "1" if self.auto_discovery.get() else "0",
                "--snmp", "1" if self.use_snmp.get() else "0",
                "--onvif", "1" if self.use_onvif.get() else "0",
                "--dahua", "1" if self.use_dahua.get() else "0",
            ]
            if relaunch_as_admin(extra):
                self.root.destroy()
            else:
                messagebox.showerror("Ошибка UAC", "Не удалось запросить повышение прав.", parent=self.root)
                self.use_sadp.set(False)
        else:
            self.use_sadp.set(False)

    # -------------------------------------------------------------- Scanning
    def start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return  # уже идёт — игнорируем повторное нажатие

        self.stop_event.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.tree.delete(*self.tree.get_children())
        self.results.clear()
        self.status_var.set("Сканирование…")

        self._scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        if not (self._scan_thread and self._scan_thread.is_alive()):
            return
        self.stop_event.set()
        self.stop_btn.config(state="disabled")
        self.status_var.set("Остановка…")

    def run_scan(self):
        all_devices: list[dict] = []
        stopped = False
        try:
            # --- SNMP ---
            if self.use_snmp.get() and not self.auto_discovery.get():
                subnet_str = self.subnet_entry.get().strip()
                try:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                except ValueError as exc:
                    messagebox.showerror("Ошибка", f"Неверная подсеть: {exc}")
                    return
                community = self.community_entry.get()
                version = self.snmp_version.get()
                for ip in network.hosts():
                    if self.stop_event.is_set():
                        stopped = True
                        break
                    res = snmp_get(str(ip), version, community=community)
                    if res.get("sysDescr") and "Error" not in res["sysDescr"] \
                            and "Exception" not in res["sysDescr"]:
                        all_devices.append({"ip": str(ip), "protocol": "SNMP", **res})

            # --- ONVIF ---
            if not stopped and self.stop_event.is_set():
                stopped = True
            if not stopped and self.use_onvif.get():
                self._set_status("ONVIF: поиск…")
                for dev in discover_onvif(
                    timeout=5, broadcast_fallback=True, stop_event=self.stop_event,
                ):
                    all_devices.append({
                        "ip": dev["ip"], "protocol": "ONVIF",
                        "info": f"XAddrs: {dev.get('xaddrs', [])}",
                    })

            # --- SADP ---
            if not stopped and self.stop_event.is_set():
                stopped = True
            if not stopped and self.use_sadp.get():
                if not is_admin():
                    all_devices.append({"ip": "", "protocol": "SADP",
                                        "info": "Пропущено: нет прав администратора"})
                else:
                    self._set_status("SADP: поиск…")
                    try:
                        for dev in discover_hikvision_sadp(
                            timeout=5.0, broadcast=True, stop_event=self.stop_event,
                        ):
                            all_devices.append({
                                "ip": dev["ip"], "protocol": "SADP",
                                "info": (f"MAC: {dev['mac']}, SN: {dev['serial']}, "
                                         f"Model: {dev['model']}, FW: {dev['firmware']}, "
                                         f"Activated: {dev['activated']}"),
                            })
                    except Exception as exc:
                        all_devices.append({"ip": "", "protocol": "SADP",
                                            "info": f"Ошибка: {exc}"})

            # --- Dahua ---
            if not stopped and self.stop_event.is_set():
                stopped = True
            if not stopped and self.use_dahua.get():
                self._set_status("Dahua: поиск…")
                try:
                    for dev in discover_dahua(timeout=5.0, stop_event=self.stop_event):
                        all_devices.append({
                            "ip": dev["ip"], "protocol": "Dahua",
                            "info": (f"MAC: {dev['mac']}, SN: {dev['serial']}, "
                                     f"Model: {dev['model']}, FW: {dev['firmware']}, "
                                     f"Activated: {dev['activated']}"),
                        })
                except Exception as exc:
                    all_devices.append({"ip": "", "protocol": "Dahua",
                                        "info": f"Ошибка: {exc}"})

        finally:
            self.results = all_devices
            # ВАЖНО: если пользователь нажал Стоп — фиксируем факт остановки
            if self.stop_event.is_set():
                stopped = True
            self.root.after(0, lambda: self.update_treeview(stopped))

    def _set_status(self, text: str):
        self.root.after(0, lambda: self.status_var.set(text))

    def update_treeview(self, stopped: bool = False):
        seen: set[tuple[str, str]] = set()
        for dev in self.results:
            key = (dev.get("ip", ""), dev.get("protocol", ""))
            if key in seen:
                continue
            seen.add(key)
            self.tree.insert(
                "", "end",
                values=(dev.get("ip", ""), dev.get("protocol", ""), dev.get("info", "")),
            )
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if stopped:
            self.status_var.set(f"Остановлено. Найдено устройств: {len(seen)}")
        else:
            self.status_var.set(f"Найдено устройств: {len(seen)}")

    # -------------------------------------------------------------- Export
    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
        )
        if filename:
            export_to_csv(self.results, filename)
            messagebox.showinfo("Экспорт", f"Данные сохранены в {filename}")


# --------------------------------------------------------------------- CLI
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--elevated", action="store_true")
    p.add_argument("--subnet")
    p.add_argument("--community")
    p.add_argument("--snmp-version", dest="snmp_version")
    p.add_argument("--auto")
    p.add_argument("--snmp")
    p.add_argument("--onvif")
    p.add_argument("--dahua")
    args, _ = p.parse_known_args()
    return args


def build_restore_dict(args: argparse.Namespace) -> dict:
    restore: dict = {}
    if args.subnet: restore["subnet"] = args.subnet
    if args.community: restore["community"] = args.community
    if args.snmp_version: restore["snmp_version"] = args.snmp_version
    if args.auto is not None: restore["auto"] = args.auto == "1"
    if args.snmp is not None: restore["snmp"] = args.snmp == "1"
    if args.onvif is not None: restore["onvif"] = args.onvif == "1"
    if args.dahua is not None: restore["dahua"] = args.dahua == "1"
    return restore


def main():
    args = parse_args()
    restore = build_restore_dict(args)
    root = tk.Tk()
    set_window_icon(root)
    CameraScannerApp(root, elevated=args.elevated, restore=restore)
    root.mainloop()


if __name__ == "__main__":
    main()