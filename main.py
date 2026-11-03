# main.py
import argparse
import ctypes
import ipaddress
import os
import sys
import threading
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
from arp_scanner import arp_scan
from port_scanner import port_scan
from isapi_scanner import isapi_probe
from net_utils import get_local_subnets
from exporter import export_to_csv


# ------------------------------------------------------------------ constants
APP_NAME = "CameraScanner"
APP_VERSION = "1.3.0"
APP_AUTHOR = "Andew Geben"
APP_COPYRIGHT = f"© 2025 {APP_AUTHOR}. Все права защищены."
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
        None, "runas", executable, " ".join(args), None, 1
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
            sv_ttk.set_theme(darkdetect.theme() if _DARKDETECT_OK and darkdetect.theme() else "light")
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
        is_dark = sv_ttk.get_theme() == "dark"
        style.configure("Footer.TLabel",
                        foreground="#888888" if is_dark else "#666666")
        style.configure("Hint.TLabel",
                        foreground="#8a8a8a" if is_dark else "#777777",
                        font=("Segoe UI", 8))
        # Стили для окна «Способы сканирования»
        style.configure("MethodTitle.TLabel",
                        font=("Segoe UI", 11, "bold"))
        style.configure("MethodBadge.TLabel",
                        font=("Segoe UI", 8),
                        foreground="#2f6fbc" if not is_dark else "#7db4f2")
        style.configure("MethodText.TLabel",
                        font=("Segoe UI", 9),
                        foreground="#333333" if not is_dark else "#dddddd")

    # ------------------------------------------------------------- UI build
    def _build_ui(self):
        r = self._restore

        main = ttk.Frame(self.root, padding=(12, 10, 12, 10))
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=0, minsize=self.LEFT_PANEL_MINWIDTH)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        # ======================= ВЕРХ: только подсеть =======================
        top_frame = ttk.LabelFrame(main, text=" Параметры сети ", padding=(12, 8))
        top_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        ttk.Label(top_frame, text="Подсеть (CIDR):").grid(row=0, column=0, sticky="w")
        self.subnet_entry = ttk.Entry(top_frame, width=24)
        self.subnet_entry.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.subnet_entry.insert(0, r.get("subnet", "192.168.1.0/24"))

        ttk.Label(top_frame, text="Пример: 192.168.1.0/24").grid(
            row=0, column=2, sticky="w", padx=(12, 0))
        top_frame.columnconfigure(3, weight=1)

        # ============================ ЛЕВАЯ ПАНЕЛЬ ============================
        left = ttk.Frame(main)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 10))

        # ---- SNMP ----
        snmp_frame = ttk.LabelFrame(left, text=" SNMP ", padding=(12, 8))
        snmp_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(snmp_frame, text="Community:").grid(row=0, column=0, sticky="w", pady=2)
        self.community_entry = ttk.Entry(snmp_frame, width=18)
        self.community_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=2)
        self.community_entry.insert(0, r.get("community", "public"))

        ttk.Label(snmp_frame, text="Version:").grid(row=1, column=0, sticky="w", pady=2)
        self.snmp_version = ttk.Combobox(
            snmp_frame, values=["v1", "v2c", "v3"], width=8, state="readonly")
        self.snmp_version.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=2)
        self.snmp_version.set(r.get("snmp_version", "v2c"))

        snmp_frame.columnconfigure(1, weight=1)

        # ---- Режим ----
        mode_frame = ttk.LabelFrame(left, text=" Режим ", padding=(12, 8))
        mode_frame.pack(fill="x", pady=(0, 8))

        self.auto_discovery = tk.BooleanVar(value=r.get("auto", False))
        self.auto_cb = ttk.Checkbutton(
            mode_frame,
            text="Автообнаружение (все интерфейсы)",
            variable=self.auto_discovery,
            command=self.on_auto_toggle,
        )
        self.auto_cb.pack(anchor="w")

        ttk.Label(mode_frame,
                  text="Игнорирует поле подсети. Ищет сразу\nво всех локальных сетях.",
                  style="Hint.TLabel", justify="left").pack(anchor="w", padx=(22, 0), pady=(2, 0))

        # ---- Протоколы (плоский список) ----
        proto = ttk.LabelFrame(left, text=" Протоколы обнаружения ", padding=(12, 8))
        proto.pack(fill="x", pady=(0, 8))

        self.use_snmp     = tk.BooleanVar(value=r.get("snmp", True))
        self.use_onvif    = tk.BooleanVar(value=r.get("onvif", True))
        self.use_sadp     = tk.BooleanVar(value=r.get("sadp", False))
        self.use_dahua    = tk.BooleanVar(value=r.get("dahua", True))
        self.use_arp      = tk.BooleanVar(value=r.get("arp", False))
        self.use_portscan = tk.BooleanVar(value=r.get("portscan", False))
        self.use_isapi    = tk.BooleanVar(value=r.get("isapi", False))

        self.snmp_cb = ttk.Checkbutton(proto, text="SNMP (MIB-II + vendor OID)",
                                       variable=self.use_snmp)
        self.snmp_cb.pack(anchor="w", pady=3)

        ttk.Checkbutton(proto, text="ONVIF WS-Discovery",
                        variable=self.use_onvif).pack(anchor="w", pady=3)

        self.sadp_cb = ttk.Checkbutton(
            proto, text="SADP (Hikvision)",
            variable=self.use_sadp, command=self.on_sadp_toggle)
        self.sadp_cb.pack(anchor="w", pady=3)
        ttk.Label(proto,
                  text="требует прав администратора; при включении будет запрос UAC",
                  style="Hint.TLabel", justify="left").pack(anchor="w", padx=(22, 0), pady=(0, 4))

        ttk.Checkbutton(proto, text="Dahua / Amcrest",
                        variable=self.use_dahua).pack(anchor="w", pady=3)

        ttk.Checkbutton(proto, text="ARP (ping sweep)",
                        variable=self.use_arp).pack(anchor="w", pady=3)

        ttk.Checkbutton(proto, text="TCP port scan (80, 443, 554, 8000, …)",
                        variable=self.use_portscan).pack(anchor="w", pady=3)

        ttk.Checkbutton(proto, text="ISAPI probe (Hikvision HTTP)",
                        variable=self.use_isapi).pack(anchor="w", pady=3)

        if self.elevated or is_admin():
            self.use_sadp.set(True)

        # ---- Кнопки действий ----
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill="x", pady=(4, 0))

        self.scan_btn = ttk.Button(btn_frame, text="▶  Сканировать", command=self.start_scan)
        self.scan_btn.pack(fill="x", ipady=3)

        self.stop_btn = ttk.Button(btn_frame, text="■  Стоп", command=self.stop_scan,
                                   state="disabled")
        self.stop_btn.pack(fill="x", pady=(6, 0), ipady=3)

        # ============================ ПРАВАЯ ПАНЕЛЬ ============================
        right = ttk.Frame(main)
        right.grid(row=1, column=1, sticky="nsew")

        tree_frame = ttk.LabelFrame(right, text=" Результаты ", padding=(6, 4))
        tree_frame.pack(fill="both", expand=True)

        columns = ("ip", "mac", "protocol", "info")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        self.tree.heading("ip", text="IP-адрес")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("protocol", text="Протокол")
        self.tree.heading("info", text="Информация")
        self.tree.column("ip",       width=130, minwidth=110, stretch=False, anchor="w")
        self.tree.column("mac",      width=150, minwidth=130, stretch=False, anchor="w")
        self.tree.column("protocol", width=110, minwidth=100, stretch=False, anchor="w")
        self.tree.column("info",     width=600, minwidth=200, stretch=True,  anchor="w")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        bottom = ttk.Frame(right)
        bottom.pack(fill="x", pady=(8, 0))

        ttk.Button(bottom, text="💾  Экспорт в CSV",
                   command=self.export_csv).pack(side="left", ipadx=4, ipady=2)

        self.copyright_label = ttk.Label(
            bottom, text=APP_COPYRIGHT, anchor="center", style="Footer.TLabel")
        self.copyright_label.pack(side="left", expand=True, fill="x", padx=12)

        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

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
            command=lambda: self._set_theme("light"))
        view_menu.add_radiobutton(
            label="Тёмная тема", variable=self.theme_var, value="dark",
            command=lambda: self._set_theme("dark"))
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
        else:
            self.subnet_entry.config(state="normal")
            self.community_entry.config(state="normal")
            self.snmp_version.config(state="readonly")
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
                "--arp", "1" if self.use_arp.get() else "0",
                "--portscan", "1" if self.use_portscan.get() else "0",
                "--isapi", "1" if self.use_isapi.get() else "0",
            ]
            if relaunch_as_admin(extra):
                self.root.destroy()
            else:
                messagebox.showerror("Ошибка UAC",
                                     "Не удалось запросить повышение прав.",
                                     parent=self.root)
                self.use_sadp.set(False)
        else:
            self.use_sadp.set(False)

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
        found_ips: set[str] = set()
        stopped = False
        se = self.stop_event

        subnets: list[ipaddress.IPv4Network] = []
        if self.auto_discovery.get():
            subnets = get_local_subnets(min_hosts=4, max_hosts=4096)
            if not subnets:
                self._set_status("Не удалось определить локальные подсети")
        else:
            subnet_str = self.subnet_entry.get().strip()
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
        if self.use_snmp.get() and not self.auto_discovery.get() and subnets:
            net = subnets[0]
            community = self.community_entry.get()
            version = self.snmp_version.get()
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
        if not stopped and self.use_arp.get() and all_hosts:
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
        if not stopped and self.use_portscan.get() and all_hosts:
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
        if not stopped and self.use_onvif.get():
            self._set_status("ONVIF: поиск…")
            for dev in discover_onvif(timeout=5, broadcast_fallback=True, stop_event=se):
                all_devices.append({
                    "ip": dev["ip"], "mac": "", "protocol": "ONVIF",
                    "info": f"XAddrs: {dev.get('xaddrs', [])}",
                })
                found_ips.add(dev["ip"])

        # SADP
        if not stopped and se.is_set():
            stopped = True
        if not stopped and self.use_sadp.get():
            if not is_admin():
                all_devices.append({"ip": "", "mac": "", "protocol": "SADP",
                                    "info": "Пропущено: нет прав администратора"})
            else:
                self._set_status("SADP: поиск…")
                try:
                    for dev in discover_hikvision_sadp(timeout=5.0, broadcast=True, stop_event=se):
                        all_devices.append({
                            "ip": dev["ip"], "mac": dev.get("mac", ""),
                            "protocol": "SADP",
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
        if not stopped and self.use_dahua.get():
            self._set_status("Dahua: поиск…")
            try:
                for dev in discover_dahua(timeout=5.0, stop_event=se):
                    all_devices.append({
                        "ip": dev["ip"], "mac": dev.get("mac", ""),
                        "protocol": "Dahua",
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
        if not stopped and self.use_isapi.get() and found_ips:
            self._set_status(f"ISAPI: проба {len(found_ips)} хостов…")
            for ip in sorted(found_ips):
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
        self.results = all_devices
        self.root.after(0, lambda: self.update_treeview(stopped))

    def _set_status(self, text: str):
        self.root.after(0, lambda: self.status_var.set(text))

    def update_treeview(self, stopped: bool = False):
        seen: set[tuple] = set()
        for dev in self.results:
            key = (dev.get("ip", ""), dev.get("mac", ""),
                   dev.get("protocol", ""), dev.get("info", ""))
            if key in seen:
                continue
            seen.add(key)
            self.tree.insert("", "end", values=(
                dev.get("ip", ""), dev.get("mac", ""),
                dev.get("protocol", ""), dev.get("info", ""),
            ))
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        unique_ips = {dev.get("ip") for dev in self.results if dev.get("ip")}
        if stopped:
            self.status_var.set(
                f"Остановлено. Уникальных IP: {len(unique_ips)}; записей: {len(seen)}")
        else:
            self.status_var.set(
                f"Найдено. Уникальных IP: {len(unique_ips)}; записей: {len(seen)}")

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