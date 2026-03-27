# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('database.py', '.'), ('scanner.py', '.'), ('analyzer.py', '.'), ('guard.py', '.'), ('ai_expert.py', '.'), ('assets/autosoc_logo.png', 'assets'), ('assets/autosoc_logo_splash.png', 'assets'), ('assets/autosoc_logo_login.png', 'assets'), ('assets/app_icon.png', 'assets'), ('assets/app_icon.ico', 'assets')],
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
    name='AutoSOC_AI',
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
