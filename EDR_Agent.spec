# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

streamlit_extra = collect_data_files('streamlit') + copy_metadata('streamlit')
altair_extra = collect_data_files('altair') + copy_metadata('altair')

a = Analysis(
    ['tray_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('dashboards', 'dashboards'),
        ('collector', 'collector'),
        ('backend', 'backend'),
        ('.env', '.'),
        ('xgboost/xgboost_sysmon_model.json', 'xgboost'),
        ('xgboost/label_encoders.pkl', 'xgboost'),
        ('xgboost/threat_predictor.py', 'xgboost'),
    ] + streamlit_extra + altair_extra,
    hiddenimports=[
        'streamlit',
        'streamlit.web.cli',
        'streamlit.runtime.scriptrunner.magic_funcs',
        'altair',
        'pandas',
        'sqlalchemy',
        'psycopg2',
        'dotenv',
    ],
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
    name='EDR_Agent',
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
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='EDR_Agent',
)
