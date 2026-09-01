# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('assets/secure_file.png', 'assets')],
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
    [],
    exclude_binaries=True,
    name='SecureFileEncryptor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/secure_file.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SecureFileEncryptor',
)
app = BUNDLE(
    coll,
    name='SecureFileEncryptor.app',
    icon='assets/secure_file.icns',
    bundle_identifier='com.securefileencryptor.app',
)
