# -*- mode: python ; coding: utf-8 -*-

import os

npcap_dir = r"C:\Windows\System32\Npcap"
binaries = []

for dll_name in ("wpcap.dll", "Packet.dll"):
    dll_path = rf"{npcap_dir}\{dll_name}"
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
    ],
    hiddenimports=['win32evtlog', 'win32evtlogutil', 'pywintypes'],
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
    uac_admin=True,
    icon='assets/app_icon.ico',
)
