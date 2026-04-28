# PyInstaller spec for the Wraith desktop launcher.
from pathlib import Path


repo_root = Path(SPECPATH).parents[1]

datas = [
    (str(repo_root / "api_server.py"), "."),
    (str(repo_root / "scanner"), "scanner"),
    (str(repo_root / "scanner-terminal" / "build"), "scanner-terminal/build"),
]

hiddenimports = [
    "engineio.async_drivers.threading",
    "playwright.sync_api",
]

a = Analysis(
    [str(repo_root / "desktop" / "wraith_desktop.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WraithDesktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="WraithDesktop",
)
