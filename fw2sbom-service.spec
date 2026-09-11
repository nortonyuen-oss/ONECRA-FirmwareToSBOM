# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the single-file service executable.
#
# datas must carry the signature packs as well as the branding images: without
# signatures/ the frozen exe starts and then finds nothing in every firmware it
# is given. fw2sbom._resource_dir() reads them back out of sys._MEIPASS.

a = Analysis(
    ['service.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('onecra_logo.png', '.'),
        ('onecra_icon.png', '.'),
        ('signatures', 'signatures'),
    ],
    hiddenimports=[],
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
    name='fw2sbom-service',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
