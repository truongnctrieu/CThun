# -*- mode: python -*-

block_cipher = None


a = Analysis(['cthun.py'],
             pathex=['C:\\Users\\Administrator.WIN7\\Desktop\\CThun'],
             binaries=[],
             datas=[],
             hiddenimports=['ssh2.agent',
             'ssh2.agent',
             'ssh2.pkey',
             'ssh2.exceptions',
             'ssh2.sftp',
             'ssh2.sftp_handle',
             'ssh2.channel', 'ssh2.listener',
             'ssh2.statinfo', 'ssh2.knownhost',
             'ssh2.error_codes', 'ssh2.fileinfo',
             'ssh2.utils',
             'ssh2.publickey'
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='cthun',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
