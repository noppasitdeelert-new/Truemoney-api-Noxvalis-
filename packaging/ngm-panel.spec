# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a single standalone ngm-panel.exe (no console window tricks).

Build (from the repository root):
    py -m pip install pyinstaller
    py -m PyInstaller packaging/ngm-panel.spec --noconfirm

Output: dist/ngm-panel.exe
"""

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

datas = [
    ("ngm_panel/data/allowed_targets.json", "ngm_panel/data"),
]

hiddenimports = collect_submodules("ngm_panel.commands") + [
    "ngm_panel.osint_data",
    "ngm_panel.osint_platforms",
    "ngm_panel.osint_sources",
    "ngm_panel.osint_tools",
    "ngm_panel.osint_catalog",
]

a = Analysis(
    ["ngm_panel/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc", "email", "http.server"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ngm-panel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # ngm-panel is a terminal tool
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="packaging/ngm-panel.ico" if __import__("os").path.exists("packaging/ngm-panel.ico") else None,
)
