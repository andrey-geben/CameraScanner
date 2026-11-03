# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec для CameraScanner (с темой sv-ttk).

Сборка:
    pyinstaller CameraScanner.spec --noconfirm
"""

import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# ---------------------------------------------------------------- пути к ресурсам
ICON_PATH = os.path.join(SPECPATH, "assets", "app.ico")
if not os.path.isfile(ICON_PATH):
    raise SystemExit(
        f"[CameraScanner.spec] Не найден файл иконки: {ICON_PATH}\n"
        f"Положите multi-size .ico в assets/app.ico и пересоберите."
    )

# ---------------------------------------------------------------- hiddenimports
# pysnmp и MIB-модули
hiddenimports = collect_submodules("pysnmp")
hiddenimports += [
    "pysnmp.smi",
    "pysnmp.smi.mibs",
    "pysnmp.smi.mibs.SNMPv2-MIB",
    "pysnmp.smi.mibs.SNMPv2-SMI",
    "pysnmp.smi.mibs.SNMPv2-TC",
    "pysnmp.smi.mibs.SNMPv2-CONF",
    "pysnmp.smi.mibs.RFC1213-MIB",
]
# SNMPv3 auth/priv
hiddenimports += collect_submodules("pyasn1")
hiddenimports += collect_submodules("Cryptodome")
# WS-Discovery
hiddenimports += ["wsdiscovery", "netifaces"]
# --- Тема sv-ttk ---
hiddenimports += ["sv_ttk", "darkdetect"]

# ----------------------------------------------------------------------- datas
datas = [
    (ICON_PATH, "assets"),
]
# Добавляем файлы темы sv_ttk (sv.tcl и ресурсы)
datas += collect_data_files("sv_ttk")

# ---------------------------------------------------------------------- анализ
a = Analysis(
    ["main.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter.test",
        "test",
        "unittest",
        "pydoc_data",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

# ------------------------------------------------------------------------ EXE
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CameraScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH,
)