# PyInstaller spec for the cross-platform Tk desktop shell.
# Build on Windows with: powershell -ExecutionPolicy Bypass -File build-windows.ps1
from pathlib import Path

tray_imports = []
try:
    import pystray  # noqa: F401
    import PIL  # noqa: F401
    tray_imports = ["pystray", "pystray._win32", "PIL", "PIL.Image", "PIL.ImageDraw"]
except ImportError:
    pass

ROOT = Path(SPECPATH).parent
ENTRY = ROOT / "portable" / "agentreins_desktop.py"
BUILD_VERSION_DIR = ROOT / "build" / "agentreins-version"

a = Analysis(
    [str(ENTRY)],
    pathex=[str(ROOT / "portable"), str(ROOT), str(BUILD_VERSION_DIR)],
    binaries=[],
    datas=[],
    # The desktop shell loads tray support lazily so source runs remain
    # dependency-free. Include it in release binaries when installed.
    hiddenimports=tray_imports + [
        "update_checker", "agent_adapters", "operations_runtime", "turn_journal",
        "evidence_projection", "safety_features", "operations_cli",
        # These modules are imported lazily from the projection/runtime path.
        # PyInstaller's AST walk does not reliably retain imports nested in
        # fallback ``try`` blocks, so keep them explicit for frozen builds.
        "provider_config", "process_rules",
    ],
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
