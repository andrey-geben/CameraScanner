# main.py
import argparse
import ctypes
import ipaddress
import os
import subprocess
import sys
import threading
import tkinter as tk
import urllib.parse
import webbrowser
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
from arp_scanner import arp_scan
from port_scanner import port_scan
from isapi_scanner import isapi_probe
from net_utils import get_local_subnets
from exporter import export_to_csv
from device_merge import merge_devices
from ssdp_scanner import discover_ssdp
from mdns_scanner import discover_mdns
from stream_player import StreamPlayerWindow


# ------------------------------------------------------------------ constants
APP_NAME = "CameraScanner"
APP_VERSION = "1.7.0"
APP_AUTHOR = "Andrew Genben"
APP_COPYRIGHT = f"© 2025–2026 {APP_AUTHOR}. Все права защищены."
APP_DESCRIPTION = (
    "Утилита активного поиска IP-камер в локальной сети.\n"
    "Протоколы: SNMP, ONVIF WS-Discovery, SADP (Hikvision), Dahua,\n"
    "ARP, TCP port scan, ISAPI probe."
)
APP_LICENSE = "Распространяется по лицензии MIT."


# Описание способов сканирования.
# Каждый элемент: (заголовок, краткая метка режима, текст).
SCAN_METHODS = [
    (
        "SNMP (v1 / v2c / v3)",
        "Active · перебор подсети",
        "Активный опрос по UDP/161 каждого адреса подсети. Извлекаются стандартные "
        "поля MIB-II (sysDescr, sysObjectID, sysName, sysLocation) и вендорские OID "
        "Hikvision. Возвращает модель, имя устройства, местоположение. Медленнее "
        "остальных методов (по 1 запросу на IP), но единственный способ пробиться "
        "за маршрутизатор при условии, что SNMP открыт."
    ),
    (
        "ONVIF WS-Discovery",
        "Broadcast / multicast · без указания подсети",
        "Стандартный механизм ONVIF. Клиент отправляет SOAP-сообщение Probe на "
        "multicast-адрес 239.255.255.250 порт 3702; камеры отвечают ProbeMatch "
        "с XAddrs. Используется библиотека wsdiscovery + собственный "
        "broadcast-фоллбэк на случай, если multicast в сегменте зарезан. "
        "Работает только в пределах одного широковещательного домена (VLAN)."
    ),
    (
        "SADP (Hikvision)",
        "Broadcast / multicast · требует прав администратора",
        "Фирменный протокол Hikvision. Запрос отправляется в multicast-группы "
        "239.255.255.250 и 239.255.255.230 на UDP/37020 и продублирован "
        "broadcast-ом во все интерфейсы. Возвращает MAC, серийный номер, модель, "
        "версию прошивки и статус активации. Права администратора нужны из-за "
        "особенностей прошивок при работе с raw-сокетами. При включении чекбокса "
        "приложение запрашивает UAC и перезапускается с сохранением всех настроек."
    ),
    (
        "Dahua / Amcrest",
        "Broadcast · без указания подсети",
        "Проприетарный протокол Dahua. JSON-запрос отправляется broadcast-ом на "
        "UDP/37810, ответ содержит MAC, серийный номер, модель, версию прошивки и "
        "статус активации. Часто срабатывает там, где ONVIF отключён — типичный "
        "заводской сценарий. Работает только в пределах одного L2-сегмента."
    ),
    (
        "ARP (ping sweep)",
        "Active · перебор подсети",
        "Параллельный ICMP-пинг всех адресов подсети (64 потока) с последующим "
        "чтением системной ARP-таблицы. Находит «молчащие» устройства, которые не "
        "отвечают на SADP/ONVIF/SNMP, но физически присутствуют в сети. MAC "
        "заполняется для всех, кто появился в ARP-таблице. Прав администратора "
        "не требует. Быстро — /24 обычно за 2–3 секунды."
    ),
    (
        "TCP port scan",
        "Active · перебор подсети",
        "Проверка открытости портов, характерных для камер и NVR: 80 (HTTP), "
        "443 (HTTPS), 554 (RTSP), 8000 (Hikvision SDK), 8080, 8443, 37777 "
        "(Dahua SDK), 34567 (XMEye). Если открыт 8000 — это почти наверняка "
        "Hikvision; если 37777 — Dahua. Помогает отличить камеру от принтера "
        "или рабочей станции, даже когда все службы обнаружения выключены. "
        "128 потоков, /24 обычно за 5–10 секунд."
    ),
    (
        "ISAPI probe (Hikvision)",
        "Active · по найденным хостам",
        "Проба HTTP-API Hikvision. По каждому найденному IP отправляется "
        "GET /ISAPI/System/deviceInfo на порты 80 и 443. При удаче (200) "
        "извлекаются модель, серийный номер, версия прошивки. Если камера "
        "требует Digest-аутентификацию (401), из заголовка WWW-Authenticate "
        "извлекаются realm и серийный номер. Даже без авторизации этого "
        "достаточно, чтобы подтвердить: это действительно Hikvision, а не "
        "просто веб-сервер."
    ),
]


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
        None, "runas", executable, subprocess.list2cmdline(args), None, 1
    )
    return result > 32


def apply_theme_to_titlebar(root: tk.Tk) -> None:
    try:
        import pywinstyles
    except ImportError:
        return
    if sys.platform != "win32":
        return
    version = sys.getwindowsversion()
    if version.major == 10 and version.build >= 22000:
        pywinstyles.change_header_color(root, "#15181C")
        pywinstyles.apply_style(root, "dark")
    elif version.major == 10:
        pywinstyles.apply_style(root, "dark")
        root.wm_attributes("-alpha", 0.99)
        root.wm_attributes("-alpha", 1)


# ---------------------------------------------------------------------- GUI
class CameraScannerApp:
    LEFT_PANEL_MINWIDTH = 340

    def __init__(self, root: tk.Tk, elevated: bool = False, restore: dict | None = None):
        self.root = root
        self.root.title(f"{APP_NAME} — IP Camera Discovery")
        self.root.geometry("1240x740")
        self.root.minsize(1040, 620)
        self.results: list[dict] = []
        self.elevated = elevated
        self.stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._restore = restore or {}

        try:
            sv_ttk.set_theme("dark")
        except Exception:
            sv_ttk.set_theme("light")
        apply_theme_to_titlebar(self.root)

        self._init_styles()
        self._build_menu()
        self._build_ui()

        self.on_auto_toggle()

        if self.elevated and self._restore.get("autostart", True):
            self.root.after(300, self.start_scan)

    # ------------------------------------------------------------- styles
    def _init_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg = "#15181C"
        panel = "#1B2026"
        card = "#20262E"
        border = "#2E3740"
        text = "#E6EDF3"
        muted = "#8B949E"
        accent = "#E6A100"
        danger = "#F85149"

        self.root.configure(bg=bg)
        style.configure(".", background=bg, foreground=text,
                        fieldbackground=card, bordercolor=border,
                        focuscolor=accent)
        style.configure("TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("Card.TFrame", background=card)
        style.configure("TLabel", background=bg, foreground=text,
                        font=("Segoe UI", 9))
        style.configure("Panel.TLabel", background=panel, foreground=text)
        style.configure("Title.TLabel", background=bg, foreground=accent,
                        font=("Segoe UI Semibold", 15))
        style.configure("Subtitle.TLabel", background=bg, foreground=muted,
                        font=("Consolas", 8))
        style.configure("Section.TLabel", background=panel, foreground=accent,
                        font=("Segoe UI Semibold", 9))
        style.configure("Muted.TLabel", background=bg, foreground=muted)
        style.configure("Footer.TLabel", background=panel, foreground=muted,
                        font=("Consolas", 8))
        style.configure("Hint.TLabel", background=panel, foreground=muted,
                        font=("Segoe UI", 8))
        style.configure("TLabelframe", background=panel, bordercolor=border,
                        relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=panel,
                        foreground=accent, font=("Segoe UI Semibold", 9))

        style.configure("TButton", background=card, foreground=text,
                        bordercolor=border, focuscolor=accent,
                        padding=(10, 5), font=("Segoe UI", 9))
        style.map("TButton",
                  background=[("active", "#2A323C"), ("disabled", panel)],
                  foreground=[("disabled", muted)])
        style.configure("Accent.TButton", background=accent, foreground="#15181C",
                        font=("Segoe UI Semibold", 9))
        style.map("Accent.TButton",
                  background=[("active", "#F0B84A")],
                  foreground=[("disabled", muted)])
        style.configure("Danger.TButton", background="#3A2224", foreground="#FFB3B3",
                        bordercolor="#6E2A2E")
        style.map("Danger.TButton", background=[("active", "#4A2A2D")])

        style.configure("TEntry", fieldbackground=card, foreground=text,
                        insertcolor=text, bordercolor=border, padding=4)
        style.map("TEntry", bordercolor=[("focus", accent)])
        style.configure("TCombobox", fieldbackground=card, background=card,
                        foreground=text, arrowcolor=accent, bordercolor=border,
                        padding=3)
        style.map("TCombobox", fieldbackground=[("readonly", card)])

        style.configure("TCheckbutton", background=panel, foreground=text,
                        font=("Segoe UI", 9))
        style.map("TCheckbutton",
                  background=[("active", panel)],
                  foreground=[("disabled", muted)])

        style.configure("TNotebook", background=bg, bordercolor=border,
                        tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=panel, foreground=muted,
                        padding=(12, 7), font=("Segoe UI Semibold", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", card)],
                  foreground=[("selected", accent)])

        style.configure("Treeview", background=card, fieldbackground=card,
                        foreground=text, rowheight=25, bordercolor=border,
                        font=("Consolas", 9))
        style.configure("Treeview.Heading", background=panel, foreground=accent,
                        font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview",
                  background=[("selected", "#2D3A46")],
                  foreground=[("selected", text)])
        style.configure("TScrollbar", background=panel, troughcolor=bg,
                        bordercolor=border, arrowcolor=muted)
        style.configure("TSeparator", background=border)

    # ------------------------------------------------------------- UI build
    def _build_ui(self):
        r = self._restore
        # Не выходим за рабочую область экрана (1080p при 125% масштабе — частая ловушка)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{min(1440, sw - 80)}x{min(900, sh - 120)}")
        self.root.minsize(1200, 700)

        # ============================ ВЕРХНЯЯ ПАНЕЛЬ ============================
        top = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 10))
        top.pack(side="top", fill="x")
        brand = ttk.Frame(top, style="Panel.TFrame")
        brand.pack(side="left")
        ttk.Label(brand, text="CAMERASCANNER", style="Title.TLabel").pack(anchor="w")
        ttk.Label(brand, text="NETWORK DISCOVERY // IP CAMERAS",
                  style="Subtitle.TLabel").pack(anchor="w")

        controls = ttk.Frame(top, style="Panel.TFrame")
        controls.pack(side="right")
        ttk.Label(controls, text="ПОДСЕТЬ", style="Panel.TLabel").pack(side="left")
        self.subnet_entry = ttk.Entry(controls, width=20)
        self.subnet_entry.pack(side="left", padx=(6, 12))
        self.subnet_entry.insert(0, r.get("subnet", "192.168.1.0/24"))
        self.auto_discovery = tk.BooleanVar(value=r.get("auto", False))
        self.auto_cb = ttk.Checkbutton(
            controls, text="AUTO", variable=self.auto_discovery,
            command=self.on_auto_toggle)
        self.auto_cb.pack(side="left", padx=(0, 12))
        self.scan_btn = ttk.Button(controls, text="▶  СКАН", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side="left", ipady=2)
        self.stop_btn = ttk.Button(controls, text="■  СТОП", style="Danger.TButton",
                                   command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(6, 0), ipady=2)

        # ============================ НИЖНИЙ СТАТУС ============================
        footer = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 6))
        footer.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(footer, textvariable=self.status_var, style="Footer.TLabel").pack(side="left")
        self.copyright_label = ttk.Label(footer, text=APP_COPYRIGHT, style="Footer.TLabel")
        self.copyright_label.pack(side="right")

        # ============================ ТЕЛО: 3 ЗОНЫ ============================
        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=(10, 8))
        sidebar = ttk.Frame(body, width=280, style="Panel.TFrame", padding=(8, 8))
        body.add(sidebar, weight=0)
        content = ttk.Frame(body)
        body.add(content, weight=1)

        # ---------------------------- ЛЕВАЯ ПАНЕЛЬ ----------------------------
        notebook = ttk.Notebook(sidebar)
        notebook.pack(fill="both", expand=True)
        search_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        access_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        notebook.add(search_tab, text="ПОИСК")
        notebook.add(access_tab, text="ДОСТУП")

        # ---- вкладка «Поиск» ----
        self.use_snmp     = tk.BooleanVar(value=r.get("snmp", True))
        self.use_onvif    = tk.BooleanVar(value=r.get("onvif", True))
        self.use_sadp     = tk.BooleanVar(value=r.get("sadp", False))
        self.use_dahua    = tk.BooleanVar(value=r.get("dahua", True))
        self.use_arp      = tk.BooleanVar(value=r.get("arp", False))
        self.use_portscan = tk.BooleanVar(value=r.get("portscan", False))
        self.use_isapi    = tk.BooleanVar(value=r.get("isapi", False))
        self.use_ssdp     = tk.BooleanVar(value=r.get("ssdp", True))
        self.use_mdns     = tk.BooleanVar(value=r.get("mdns", True))

        ttk.Label(search_tab, text="МЕТОДЫ ОБНАРУЖЕНИЯ", style="Section.TLabel").pack(
            anchor="w", pady=(0, 6))
        methods = ttk.Frame(search_tab, style="Panel.TFrame")
        methods.pack(fill="x")
        method_defs = [
            ("SNMP", self.use_snmp), ("ONVIF", self.use_onvif),
            ("SADP", self.use_sadp), ("Dahua", self.use_dahua),
            ("SSDP", self.use_ssdp), ("mDNS", self.use_mdns),
            ("ARP", self.use_arp), ("Port scan", self.use_portscan),
            ("ISAPI", self.use_isapi),
        ]
        for i, (label, var) in enumerate(method_defs):
            cb = ttk.Checkbutton(methods, text=label, variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky="w", padx=2, pady=3)
            if label == "SNMP":
                self.snmp_cb = cb
            elif label == "SADP":
                self.sadp_cb = cb
        ttk.Label(
            search_tab,
            text="SADP обычно работает без администратора.\n"
                 "Broadcast/multicast — в пределах L2-сегмента.",
            style="Hint.TLabel", justify="left").pack(anchor="w", pady=(10, 0))
        ttk.Button(search_tab, text="Способы сканирования…",
                   command=self.show_scan_methods).pack(fill="x", pady=(12, 0))

        # ---- вкладка «Доступ» ----
        snmp_box = ttk.LabelFrame(access_tab, text=" SNMP ", padding=8)
        snmp_box.pack(fill="x", pady=(0, 10))
        ttk.Label(snmp_box, text="Community", style="Hint.TLabel").grid(
            row=0, column=0, sticky="w")
        self.community_entry = ttk.Entry(snmp_box, width=18)
        self.community_entry.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        self.community_entry.insert(0, r.get("community", "public"))
        ttk.Label(snmp_box, text="Версия", style="Hint.TLabel").grid(
            row=2, column=0, sticky="w")
        self.snmp_version = ttk.Combobox(
            snmp_box, values=["v1", "v2c", "v3"], width=8, state="readonly")
        self.snmp_version.grid(row=3, column=0, sticky="w", pady=(2, 0))
        self.snmp_version.set(r.get("snmp_version", "v2c"))
        snmp_box.columnconfigure(0, weight=1)

        onvif_box = ttk.LabelFrame(access_tab, text=" ONVIF ", padding=8)
        onvif_box.pack(fill="x")
        ttk.Label(onvif_box, text="Логин", style="Hint.TLabel").grid(
            row=0, column=0, sticky="w")
        self.onvif_user = ttk.Entry(onvif_box, width=18)
        self.onvif_user.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        ttk.Label(onvif_box, text="Пароль", style="Hint.TLabel").grid(
            row=2, column=0, sticky="w")
        self.onvif_password = ttk.Entry(onvif_box, width=18, show="*")
        self.onvif_password.grid(row=3, column=0, sticky="ew", pady=(2, 0))
        onvif_box.columnconfigure(0, weight=1)
        ttk.Label(
            access_tab,
            text="ONVIF-логин нужен для DeviceInfo и RTSP-ссылок.\n"
                 "Пусто — будут только анонимные запросы.",
            style="Hint.TLabel", justify="left").pack(anchor="w", pady=(10, 0))

        if self.elevated or is_admin():
            self.use_sadp.set(True)

        # ---------------------------- ЦЕНТР: ТАБЛИЦА ----------------------------
        table_card = ttk.Frame(content, style="Card.TFrame", padding=6)
        table_card.pack(fill="both", expand=True)

        table_head = ttk.Frame(table_card, style="Card.TFrame")
        table_head.pack(fill="x", pady=(0, 4))
        ttk.Label(table_head, text="УСТРОЙСТВА", style="Section.TLabel").pack(side="left")
        self.count_label = tk.StringVar(value="0")
        ttk.Label(table_head, textvariable=self.count_label,
                  style="Muted.TLabel").pack(side="right")

        table_body = ttk.Frame(table_card, style="Card.TFrame")
        table_body.pack(fill="both", expand=True)

        columns = ("ip", "mac", "device", "protocol", "action")
        self.tree = ttk.Treeview(table_body, columns=columns, show="headings")
        self.tree.heading("ip", text="IP")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("device", text="Устройство")
        self.tree.heading("protocol", text="Протоколы")
        self.tree.heading("action", text="Инфо")
        self.tree.column("ip", width=120, minwidth=100, stretch=False, anchor="w")
        self.tree.column("mac", width=150, minwidth=120, stretch=False, anchor="w")
        self.tree.column("device", width=280, minwidth=160, stretch=True, anchor="w")
        self.tree.column("protocol", width=170, minwidth=110, stretch=False, anchor="w")
        self.tree.column("action", width=105, minwidth=90, stretch=False, anchor="center")
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self.show_device_details)

        vsb = ttk.Scrollbar(table_body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        table_body.rowconfigure(0, weight=1)
        table_body.columnconfigure(0, weight=1)

    # --------------------------------------------------------------- меню
    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Экспорт в CSV…", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.destroy)
        menubar.add_cascade(label="Файл", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        self.theme_var = tk.StringVar(value="dark")
        view_menu.add_command(
            label="Индустриальная тёмная", command=lambda: self._set_theme("dark"))
        menubar.add_cascade(label="Вид", menu=view_menu)

        # ---- Справка: два пункта ----
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Способы сканирования",
                              command=self.show_scan_methods)
        help_menu.add_separator()
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.root.config(menu=menubar)

    def _set_theme(self, theme: str):
        sv_ttk.set_theme(theme)
        self.theme_var.set(theme)
        apply_theme_to_titlebar(self.root)
        self._init_styles()

    # ---------------------------------------------------- Способы сканирования
    def show_scan_methods(self):
        """
        Модальное окно с прокручиваемым описанием всех протоколов обнаружения.
        Колесо мыши привязано только пока курсор над окном и снимается
        при любом способе закрытия (кнопка, Esc, Enter, крестик).
        """
        win = tk.Toplevel(self.root)
        win.title("Способы сканирования")
        win.transient(self.root)
        win.grab_set()
        win.geometry("720x640")
        win.minsize(560, 480)
        try:
            win.iconbitmap(default=resource_path("assets/app.ico"))
        except Exception:
            pass

        # ---- Заголовок ----
        header = ttk.Frame(win, padding=(20, 16, 20, 8))
        header.pack(fill="x")
        ttk.Label(header, text="Способы сканирования",
                  font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(
            header,
            text=("Каждый метод можно включать независимо. "
                  "Broadcast/multicast работают без указания подсети, "
                  "но в пределах одного L2-сегмента. Active — перебирают адреса "
                  "и могут пробиться за маршрутизатор."),
            wraplength=680, justify="left",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        ttk.Separator(win, orient="horizontal").pack(fill="x", padx=20)

        # ---- Прокручиваемая область ----
        body = ttk.Frame(win)
        body.pack(fill="both", expand=True, padx=20, pady=(8, 0))

        canvas = tk.Canvas(body, borderwidth=0, highlightthickness=0)
        vsb = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        inner = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_config(_event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_inner_config)

        def _on_canvas_config(event):
            # Растягиваем внутренний фрейм на всю ширину canvas
            items = canvas.find_all()
            if items:
                canvas.itemconfigure(items[0], width=event.width)
        canvas.bind("<Configure>", _on_canvas_config)

        # ---- Прокрутка колесом: только пока курсор над окном ----
        def _on_mousewheel(event):
            # Защита от «мёртвого» canvas, если событие прилетело после destroy
            try:
                if not canvas.winfo_exists():
                    return
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass

        def _bind_wheel(_event=None):
            try:
                canvas.bind_all("<MouseWheel>", _on_mousewheel)
            except tk.TclError:
                pass

        def _unbind_wheel(_event=None):
            try:
                canvas.unbind_all("<MouseWheel>")
            except tk.TclError:
                pass

        # Привязка — при входе курсора в окно, снятие — при выходе и при закрытии
        win.bind("<Enter>", _bind_wheel, add="+")
        win.bind("<Leave>", _unbind_wheel, add="+")
        win.bind("<Destroy>", _unbind_wheel, add="+")

        # ---- Пункты ----
        for idx, (title, badge, text) in enumerate(SCAN_METHODS):
            card = ttk.Frame(inner, padding=(4, 8, 4, 8))
            card.pack(fill="x", pady=(0 if idx == 0 else 6, 0))

            row = ttk.Frame(card)
            row.pack(fill="x")
            ttk.Label(row, text=title, style="MethodTitle.TLabel").pack(side="left")
            ttk.Label(row, text=f"  ·  {badge}", style="MethodBadge.TLabel").pack(
                side="left", padx=(6, 0), pady=(2, 0))

            ttk.Label(card, text=text, style="MethodText.TLabel",
                      wraplength=640, justify="left").pack(
                anchor="w", pady=(3, 0))

            if idx < len(SCAN_METHODS) - 1:
                ttk.Separator(inner, orient="horizontal").pack(
                    fill="x", pady=(2, 6))

        # ---- Футер ----
        ttk.Separator(win, orient="horizontal").pack(fill="x", padx=20, pady=(6, 0))
        footer = ttk.Frame(win, padding=(20, 10))
        footer.pack(fill="x")
        ttk.Button(footer, text="Закрыть", command=win.destroy,
                   width=14).pack(side="right")

        # Enter/Esc — закрыть
        win.bind("<Escape>", lambda e: win.destroy())
        win.bind("<Return>", lambda e: win.destroy())

        # Центрирование
        win.update_idletasks()
        px, py = self.root.winfo_rootx(), self.root.winfo_rooty()
        pw, ph = self.root.winfo_width(), self.root.winfo_height()
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")

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

        frame = ttk.Frame(win, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(frame, text=f"Версия {APP_VERSION}",
                  foreground="#555").pack(anchor="w", pady=(0, 10))
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=5)
        ttk.Label(frame, text=APP_DESCRIPTION,
                  justify="left").pack(anchor="w", pady=(5, 10))

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

    # -------------------------------------------------------- Warning dialog
    def _show_scan_warning(self) -> bool:
        win = tk.Toplevel(self.root)
        win.title("Внимание")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)
        try:
            win.iconbitmap(default=resource_path("assets/app.ico"))
        except Exception:
            pass

        outer = ttk.Frame(win, padding=24)
        outer.pack(fill="both", expand=True)

        try:
            ttk.Label(outer, text="⚠",
                      font=("Segoe UI Emoji", 36),
                      foreground="#e6a100").pack(pady=(0, 10))
        except Exception:
            ttk.Label(outer, text="!",
                      font=("Segoe UI", 36, "bold"),
                      foreground="#e6a100").pack(pady=(0, 10))

        ttk.Label(outer, text="Внимание: сетевое сканирование",
                  font=("Segoe UI", 13, "bold")).pack(pady=(0, 12))

        ttk.Label(
            outer,
            text=(
                "Вы собираетесь выполнить активное сканирование сети.\n\n"
                "Данные действия будут зафиксированы и видны службам "
                "информационной безопасности и администраторам сети.\n\n"
                "Пожалуйста, согласуйте производимые работы с ИБ-подразделением "
                "перед началом сканирования."
            ),
            justify="center", wraplength=470,
        ).pack(pady=(0, 20))

        result = {"proceed": False}

        def on_ok():
            result["proceed"] = True
            win.destroy()

        ttk.Button(outer, text="Понятно", command=on_ok, width=18).pack()

        win.bind("<Return>", lambda e: on_ok())
        win.bind("<Escape>", lambda e: win.destroy())

        win.update_idletasks()
        px, py = self.root.winfo_rootx(), self.root.winfo_rooty()
        pw, ph = self.root.winfo_width(), self.root.winfo_height()
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")

        win.wait_window()
        return result["proceed"]

    # -------------------------------------------------------------- режимы
    def on_auto_toggle(self):
        if self.auto_discovery.get():
            self.subnet_entry.config(state="disabled")
            self.community_entry.config(state="disabled")
            self.snmp_version.config(state="disabled")
            self.use_snmp.set(False)
            self.snmp_cb.config(state="disabled")
            self.use_arp.set(True)
            self.use_portscan.set(True)
            self.use_ssdp.set(True)
            self.use_mdns.set(True)
        else:
            self.subnet_entry.config(state="normal")
            self.community_entry.config(state="normal")
            self.snmp_version.config(state="readonly")
            self.snmp_cb.config(state="normal")
            self.use_snmp.set(True)

    # ------------------------------------------------------------------ UAC
    def on_sadp_toggle(self):
        # SADP работает обычными UDP-сокетами и на практике не требует UAC.
        # Если конкретная система заблокирует broadcast, это проявится как ошибка в результате.
        return

    # -------------------------------------------------------------- Scanning
    def start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return

        if not self._show_scan_warning():
            return

        self.stop_event.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.tree.delete(*self.tree.get_children())
        self.results.clear()
        self.status_var.set("Сканирование…")
        settings = {
            "auto": self.auto_discovery.get(),
            "subnet": self.subnet_entry.get().strip(),
            "community": self.community_entry.get(),
            "snmp_version": self.snmp_version.get(),
            "snmp": self.use_snmp.get(),
            "onvif": self.use_onvif.get(),
            "sadp": self.use_sadp.get(),
            "dahua": self.use_dahua.get(),
            "arp": self.use_arp.get(),
            "portscan": self.use_portscan.get(),
            "isapi": self.use_isapi.get(),
            "ssdp": self.use_ssdp.get(),
            "mdns": self.use_mdns.get(),
            "onvif_user": self.onvif_user.get().strip(),
            "onvif_password": self.onvif_password.get(),
        }
        self._scan_thread = threading.Thread(
            target=self.run_scan, args=(settings,), daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        if not (self._scan_thread and self._scan_thread.is_alive()):
            return
        self.stop_event.set()
        self.stop_btn.config(state="disabled")
        self.status_var.set("Остановка…")

    def run_scan(self, settings: dict):
        """Обёртка: ошибки не должны оставлять кнопки заблокированными."""
        try:
            self._run_scan(settings)
        except Exception as exc:  # noqa: BLE001
            self.results.append({
                "ip": "", "mac": "", "protocol": "Ошибка",
                "info": f"Сканирование прервано: {exc}",
            })
            self._set_status(f"Ошибка сканирования: {exc}")
            self.root.after(0, lambda: self.update_treeview(True))

    def _run_scan(self, settings: dict):
        all_devices: list[dict] = []
        found_ips: set[str] = set()
        stopped = False
        se = self.stop_event

        subnets: list[ipaddress.IPv4Network] = []
        if settings['auto']:
            subnets = get_local_subnets(min_hosts=4, max_hosts=4096)
            if not subnets:
                self._set_status("Не удалось определить локальные подсети")
        else:
            subnet_str = settings['subnet']
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                if net.num_addresses > 4096:
                    self._set_status(
                        f"Подсеть {net} слишком велика (>4096 адресов) — пропускаем active scan"
                    )
                else:
                    subnets.append(net)
            except ValueError as exc:
                self._set_status(f"Неверная подсеть: {exc}")

        all_hosts: list[str] = []
        for net in subnets:
            all_hosts.extend(str(ip) for ip in net.hosts())

        # SNMP
        if settings['snmp'] and not settings['auto'] and subnets:
            net = subnets[0]
            community = settings['community']
            version = settings['snmp_version']
            self._set_status(f"SNMP: {net}…")
            for ip in net.hosts():
                if se.is_set():
                    stopped = True
                    break
                res = snmp_get(str(ip), version, community=community)
                if res.get("sysDescr") and "Error" not in res["sysDescr"] \
                        and "Exception" not in res["sysDescr"]:
                    info_parts = []
                    if res.get("sysDescr"):    info_parts.append(res["sysDescr"][:100])
                    if res.get("sysName"):     info_parts.append(f"Name: {res['sysName']}")
                    if res.get("sysLocation"): info_parts.append(f"Loc: {res['sysLocation']}")
                    all_devices.append({
                        "ip": str(ip), "mac": "", "protocol": "SNMP",
                        "info": " | ".join(info_parts),
                    })
                    found_ips.add(str(ip))

        # ARP
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['arp'] and all_hosts:
            self._set_status(f"ARP: ping sweep {len(all_hosts)} хостов…")
            for r in arp_scan(all_hosts, stop_event=se):
                all_devices.append({
                    "ip": r["ip"], "mac": r["mac"] or "",
                    "protocol": "ARP",
                    "info": "" if r["mac"] else "alive (no ARP entry)",
                })
                found_ips.add(r["ip"])

        # Port scan
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['portscan'] and all_hosts:
            self._set_status(f"Port scan: {len(all_hosts)} хостов…")
            for r in port_scan(all_hosts, stop_event=se):
                ports_str = ", ".join(f"{p}/{name}" for p, name in r["ports"].items())
                info = f"Open: {ports_str}"
                if r.get("vendor_hint"):
                    info += f" | {r['vendor_hint']}"
                all_devices.append({
                    "ip": r["ip"], "mac": "", "protocol": "Port scan", "info": info,
                })
                found_ips.add(r["ip"])

        # ONVIF
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['onvif']:
            self._set_status("ONVIF: поиск…")
            for dev in discover_onvif(
                timeout=5, broadcast_fallback=True, stop_event=se,
                username=settings['onvif_user'] or None,
                password=settings['onvif_password'] or None,
            ):
                bits = [f"XAddrs: {dev.get('xaddrs', [])}"]
                if dev.get("manufacturer"):
                    bits.append(f"Vendor: {dev['manufacturer']}")
                if dev.get("model"):
                    bits.append(f"Model: {dev['model']}")
                if dev.get("firmware"):
                    bits.append(f"FW: {dev['firmware']}")
                if dev.get("serial"):
                    bits.append(f"SN: {dev['serial']}")
                all_devices.append({
                    "ip": dev["ip"], "mac": "", "protocol": "ONVIF",
                    "info": " | ".join(bits),
                    "vendor": dev.get("manufacturer", ""),
                    "model": dev.get("model", ""),
                    "firmware": dev.get("firmware", ""),
                    "serial": dev.get("serial", ""),
                    "rtsp_urls": dev.get("rtsp_urls", []),
                    "rtsp_credentials": dev.get("rtsp_credentials", {}),
                })
                found_ips.add(dev["ip"])

        # SSDP / UPnP
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['ssdp']:
            self._set_status("SSDP/UPnP: поиск…")
            try:
                for dev in discover_ssdp(timeout=3.0, stop_event=se):
                    all_devices.append(dev)
                    found_ips.add(dev["ip"])
            except Exception as exc:  # noqa: BLE001
                all_devices.append({"ip": "", "mac": "", "protocol": "SSDP",
                                    "info": f"Ошибка: {exc}"})

        # mDNS / Bonjour
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['mdns']:
            self._set_status("mDNS/Bonjour: поиск…")
            try:
                for dev in discover_mdns(timeout=4.0, stop_event=se):
                    all_devices.append(dev)
                    found_ips.add(dev["ip"])
            except Exception as exc:  # noqa: BLE001
                all_devices.append({"ip": "", "mac": "", "protocol": "mDNS",
                                    "info": f"Ошибка: {exc}"})

        # SADP
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['sadp']:
            self._set_status("SADP: поиск…")
            try:
                for dev in discover_hikvision_sadp(timeout=5.0, broadcast=True, stop_event=se):
                    all_devices.append({
                        "ip": dev["ip"], "mac": dev.get("mac", ""),
                        "protocol": "SADP", "vendor": "Hikvision",
                        "model": dev.get("model", ""),
                        "firmware": dev.get("firmware", ""),
                        "serial": dev.get("serial", ""),
                        "info": (f"SN: {dev['serial']}, Model: {dev['model']}, "
                                 f"FW: {dev['firmware']}, Activated: {dev['activated']}"),
                    })
                    found_ips.add(dev["ip"])
            except Exception as exc:
                all_devices.append({"ip": "", "mac": "", "protocol": "SADP",
                                    "info": f"Ошибка: {exc}"})

        # Dahua
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['dahua']:
            self._set_status("Dahua: поиск…")
            try:
                for dev in discover_dahua(timeout=5.0, stop_event=se):
                    all_devices.append({
                        "ip": dev["ip"], "mac": dev.get("mac", ""),
                        "protocol": "Dahua", "vendor": "Dahua",
                        "model": dev.get("model", ""),
                        "firmware": dev.get("firmware", ""),
                        "serial": dev.get("serial", ""),
                        "info": (f"SN: {dev['serial']}, Model: {dev['model']}, "
                                 f"FW: {dev['firmware']}, Activated: {dev['activated']}"),
                    })
                    found_ips.add(dev["ip"])
            except Exception as exc:
                all_devices.append({"ip": "", "mac": "", "protocol": "Dahua",
                                    "info": f"Ошибка: {exc}"})

        # ISAPI
        if not stopped and se.is_set():
            stopped = True
        if not stopped and settings['isapi']:
            if found_ips:
                isapi_targets = sorted(found_ips)
            else:
                # ISAPI выбран единственным методом — проверяем первые хосты подсети
                isapi_targets = all_hosts[:32]
            if not isapi_targets:
                all_devices.append({"ip": "", "mac": "", "protocol": "ISAPI",
                                    "info": "Нет хостов для проверки (укажите подсеть)"})
            self._set_status(f"ISAPI: проба {len(isapi_targets)} хостов…")
            for ip in isapi_targets:
                if se.is_set():
                    stopped = True
                    break
                r = isapi_probe(ip, timeout=2.0)
                if not r:
                    continue
                parts = []
                if r.get("model"):             parts.append(f"Model: {r['model']}")
                if r.get("serial"):            parts.append(f"SN: {r['serial']}")
                if r.get("serial_from_realm"): parts.append(f"SN(realm): {r['serial_from_realm']}")
                if r.get("firmware"):          parts.append(f"FW: {r['firmware']}")
                if r.get("realm") and not r.get("serial_from_realm"):
                    parts.append(f"Realm: {r['realm']}")
                if r.get("server"):            parts.append(f"Server: {r['server']}")
                if r.get("auth_required"):     parts.append("Auth: required")
                if not parts:                  parts.append("ISAPI detected")
                all_devices.append({
                    "ip": ip, "mac": "", "protocol": "ISAPI",
                    "info": "; ".join(parts) + f" ({r.get('scheme','http')}:{r.get('port','')})",
                })

        if se.is_set():
            stopped = True
        self.results = merge_devices(all_devices)
        self.root.after(0, lambda: self.update_treeview(stopped))

    def _set_status(self, text: str):
        self.root.after(0, lambda: self.status_var.set(text))

    def show_device_details(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        ip = values[0] if values else ""
        dev = next((d for d in self.results if d.get("ip") == ip), None)
        if not dev:
            return

        win = tk.Toplevel(self.root)
        win.title(f"Устройство {ip or '—'}")
        win.transient(self.root)
        win.geometry("780x540")
        text = tk.Text(win, wrap="word", padx=12, pady=12)
        text.pack(fill="both", expand=True)
        lines = [
            f"IP: {dev.get('ip', '—')}",
            f"MAC: {dev.get('mac') or '—'}",
            f"Устройство: {dev.get('device') or '—'}",
            f"Протоколы: {dev.get('protocol') or '—'}",
            f"Вендор: {dev.get('vendor') or '—'}",
            f"OUI (MAC): {dev.get('oui_vendor') or '—'}",
            f"Модель: {dev.get('model') or '—'}",
            f"Прошивка: {dev.get('firmware') or '—'}",
            f"Серийник: {dev.get('serial') or '—'}",
            f"Веб: {dev.get('web_url') or '—'}",
            "",
            "RTSP-потоки:",
        ]
        urls = dev.get("rtsp_urls") or []
        lines += [f"  {u}" for u in urls] if urls else ["  —"]
        creds = dev.get("rtsp_credentials") or {}
        if creds.get("user"):
            lines += [
                "",
                "Учётные данные из ONVIF-ответа камеры:",
                f"  Пользователь: {creds.get('user', '—')}",
                "  Пароль: ••••••••",
                "  ⚠ Это данные самого устройства. Не публикуйте их.",
            ]
        lines += ["", "Доказательства:", dev.get("info") or "—"]
        text.insert("1.0", "\n".join(lines))
        text.config(state="disabled")

        bar = ttk.Frame(win, padding=(12, 0, 12, 12))
        bar.pack(fill="x")

        first = ttk.Frame(bar)
        first.pack(fill="x")
        if ip:
            ttk.Button(first, text="Копировать IP",
                       command=lambda: self._copy(ip)).pack(side="left")
        if urls:
            ttk.Button(first, text="Копировать RTSP",
                       command=lambda: self._copy(urls[0])).pack(side="left", padx=6)
            ttk.Button(first, text="▶ Смотреть поток",
                       command=lambda: self._open_stream(urls, creds, dev)).pack(
                           side="left", padx=6)
        if dev.get("web_url"):
            ttk.Button(first, text="Открыть веб",
                       command=lambda: webbrowser.open(dev["web_url"])).pack(side="left")
        ttk.Button(first, text="Закрыть", command=win.destroy).pack(side="right")

        if creds.get("user"):
            cred_bar = ttk.Frame(bar)
            cred_bar.pack(fill="x", pady=(8, 0))
            ttk.Button(
                cred_bar, text="Показать пароль",
                command=lambda: self._show_password(creds),
            ).pack(side="left")
            if urls:
                ttk.Button(
                    cred_bar, text="Копировать RTSP с паролем",
                    command=lambda: self._copy_rtsp_with_password(urls, creds),
                ).pack(side="left", padx=6)

    def _rtsp_with_credentials(self, urls: list[str], creds: dict) -> str:
        if not urls:
            return ""
        url = urls[0]
        pwd = creds.get("password", "")
        user = creds.get("user", "")
        if pwd:
            quoted = urllib.parse.quote(pwd, safe="")
            if "password=***" in url:
                url = url.replace("password=***", f"password={quoted}")
            elif ":***@" in url:
                url = url.replace(":***@", f":{quoted}@")
            else:
                parts = urllib.parse.urlsplit(url)
                if parts.hostname:
                    auth = f"{urllib.parse.quote(user, safe='')}:{quoted}@"
                    host = parts.hostname + (f":{parts.port}" if parts.port else "")
                    url = urllib.parse.urlunsplit(
                        (parts.scheme, auth + host, parts.path, parts.query, parts.fragment)
                    )
        return url

    def _copy_rtsp_with_password(self, urls: list[str], creds: dict):
        """Копирует рабочий RTSP-URL, подставляя пароль из ONVIF-ответа."""
        url = self._rtsp_with_credentials(urls, creds)
        if not url:
            return
        self._copy(url)
        messagebox.showinfo("RTSP", "Ссылка с паролем скопирована в буфер обмена.")

    def _open_stream(self, urls: list[str], creds: dict, dev: dict):
        url = self._rtsp_with_credentials(urls, creds)
        if not url:
            messagebox.showerror("Поток", "Нет RTSP-ссылки для этого устройства.")
            return
        try:
            StreamPlayerWindow(self.root, f"Поток {dev.get('ip','')}", url)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Поток", f"Не удалось открыть: {exc}")

    def _show_password(self, creds: dict):
        win = tk.Toplevel(self.root)
        win.title("Учётные данные ONVIF")
        win.transient(self.root)
        win.resizable(False, False)
        frame = ttk.Frame(win, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Логин:").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text=creds.get("user", "")).grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(frame, text="Пароль:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        entry = ttk.Entry(frame, width=32)
        entry.insert(0, creds.get("password", ""))
        entry.configure(state="readonly")
        entry.grid(row=1, column=1, sticky="w", padx=8, pady=(8, 0))
        ttk.Label(frame, text="Получено из ответа камеры. Не публикуйте; смените пароль.",
                  style="Hint.TLabel", wraplength=380).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))
        bar = ttk.Frame(frame)
        bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Button(bar, text="Копировать пароль",
                   command=lambda: self._copy(creds.get("password", ""))).pack(side="left")
        ttk.Button(bar, text="Закрыть", command=win.destroy).pack(side="right")

    def _copy(self, value: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(value)

    def _on_tree_select(self, event=None):
        return

    def _on_tree_click(self, event=None):
        if event is None:
            return
        row = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not row:
            return
        # последняя колонка — «Открыть»
        if col == f"#{len(self.tree['columns'])}":
            self.tree.selection_set(row)
            self.show_device_details()

    def update_treeview(self, stopped: bool = False):
        self.tree.delete(*self.tree.get_children())
        for dev in self.results:
            values = (
                dev.get("ip", ""), dev.get("mac", ""),
                dev.get("device", ""), dev.get("protocol", ""),
                "Открыть",
            )
            if dev.get("ip"):
                self.tree.insert("", "end", iid=dev["ip"], values=values)
            else:
                self.tree.insert("", "end", values=values)
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.count_label.set(f"{len(self.results)}")
        rows = self.tree.get_children()
        if rows:
            self.tree.selection_set(rows[0])
        unique_ips = {dev.get("ip") for dev in self.results if dev.get("ip")}
        if stopped:
            self.status_var.set(
                f"Остановлено. Уникальных IP: {len(unique_ips)}; записей: {len(self.results)}")
        else:
            self.status_var.set(
                f"Найдено. Уникальных IP: {len(unique_ips)}; записей: {len(self.results)}")

    # -------------------------------------------------------------- Export
    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
        )
        if filename:
            rows = []
            for dev in self.results:
                rows.append({
                    k: (", ".join(v) if isinstance(v, list) else v)
                    for k, v in dev.items() if k != "rtsp_credentials"
                })
            export_to_csv(rows, filename)
            messagebox.showinfo("Экспорт", f"Данные сохранены в {filename}")


# --------------------------------------------------------------------- CLI
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CameraScanner — поиск IP-камер в локальной сети")
    p.add_argument("--elevated", action="store_true")
    p.add_argument("--subnet")
    p.add_argument("--community")
    p.add_argument("--snmp-version", dest="snmp_version")
    p.add_argument("--auto")
    p.add_argument("--snmp")
    p.add_argument("--onvif")
    p.add_argument("--dahua")
    p.add_argument("--arp")
    p.add_argument("--portscan")
    p.add_argument("--isapi")
    args, _ = p.parse_known_args()
    return args


def build_restore_dict(args: argparse.Namespace) -> dict:
    r: dict = {}
    if args.subnet:        r["subnet"] = args.subnet
    if args.community:     r["community"] = args.community
    if args.snmp_version:  r["snmp_version"] = args.snmp_version
    for src, dst in (
        ("auto", "auto"), ("snmp", "snmp"), ("onvif", "onvif"),
        ("dahua", "dahua"), ("arp", "arp"), ("portscan", "portscan"),
        ("isapi", "isapi"),
    ):
        val = getattr(args, src, None)
        if val is not None:
            r[dst] = (val == "1")
    return r


def main():
    args = parse_args()
    restore = build_restore_dict(args)
    root = tk.Tk()
    set_window_icon(root)
    CameraScannerApp(root, elevated=args.elevated, restore=restore)
    root.mainloop()


if __name__ == "__main__":
    main()
