# PyInstaller spec for the cross-platform Tk desktop shell.
# Build on Windows with: powershell -ExecutionPolicy Bypass -File build-windows.ps1
from pathlib import Path

ROOT = Path(SPECPATH).parent
ENTRY = ROOT / "portable" / "agentreins_desktop.py"

a = Analysis(
    [str(ENTRY)],
    pathex=[str(ROOT / "portable"), str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
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
    a.binaries,
    a.datas,
    [],
    name="AgentReins",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
