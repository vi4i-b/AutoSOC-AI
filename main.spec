# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build configuration. Works on Windows and Linux:
#   python -m PyInstaller --clean main.spec

import os
import sys

binaries = []
hiddenimports = []

if sys.platform == "win32":
    hiddenimports = ["win32evtlog", "win32evtlogutil", "pywintypes"]
    npcap_dir = r"C:\Windows\System32\Npcap"
    for dll_name in ("wpcap.dll", "Packet.dll"):
        dll_path = os.path.join(npcap_dir, dll_name)
        if os.path.exists(dll_path):
            binaries.append((dll_path, "."))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=[
        ('assets/app_icon.png', 'assets'),
        ('assets/app_icon.ico', 'assets'),
        ('assets/autosoc_logo.png', 'assets'),
        ('assets/autosoc_logo_login.png', 'assets'),
        ('assets/autosoc_logo_splash.png', 'assets'),
        # Served to endpoints over GET /agent by the collector.
        ('agent/autosoc_agent.py', 'agent'),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AutoSOC',
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
    uac_admin=(sys.platform == "win32"),
    icon='assets/app_icon.ico' if sys.platform == "win32" else None,
)
