from stat import S_IFDIR, S_IFREG
from tempfile import NamedTemporaryFile
from time import time
import sys
import os

if not os.environ.get('FUSE_LIBRARY_PATH') and os.name == 'nt':
    os.environ.setdefault('FUSE_LIBRARY_PATH',
                          os.path.join(os.path.dirname(__file__),
                                       r"bin\winfsp-%s.dll" % ("x64" if sys.maxsize > 0xffffffff else "x86")))
try:
    from fuse import Operations, LoggingMixIn

    class MtkDaFS(LoggingMixIn, Operations):
        def __init__(self, da_handler, rw=False):
            self.da_handler = da_handler
            self.rw = rw
            self.files = {'/': dict(
                st_mode=(S_IFDIR | 0o555),
                st_ctime=time(),
                st_mtime=time(),
                st_atime=time(),
                st_nlink=2), '/emmc_user.bin': dict(
                st_mode=(S_IFREG | 0o777) if self.rw else (S_IFREG | 0o555),
                st_ctime=time(),
                st_mtime=time(),
                st_atime=time(),
                st_nlink=2,
                st_size=self.da_handler.mtk.daloader.daconfig.storage.flashsize), '/partitions': dict(
                st_mode=(S_IFDIR | 0o555),
                st_ctime=time(),
                st_mtime=time(),
                st_atime=time(),
                st_nlink=2)}

            for part in self.da_handler.mtk.daloader.get_partition_data():
                self.files[f'/partitions/{part.name}'] = dict(
                    st_mode=(S_IFREG | 0o777) if self.rw else (S_IFREG | 0o555),
                    st_ctime=time(),
                    st_mtime=time(),
                    st_atime=time(),
                    st_nlink=2,
                    st_size=part.sectors * self.da_handler.mtk.daloader.daconfig.pagesize,
                    offset=part.sector * self.da_handler.mtk.daloader.daconfig.pagesize)

        def readdir(self, path, fh):
            return ['.', '..'] + [x.removeprefix(path).removeprefix('/') for x in self.files if
                                  x.startswith(path) and x != path]

        def read(self, path, size, offset, fh):
            if size + offset > self.files[path]['st_size']:
                return b''
            file_offset = 0
            if 'offset' in self.files[path]:
                file_offset = self.files[path]['offset']
            data = self.da_handler.da_ro(start=file_offset + offset, length=size, filename='', parttype=None)
            return bytes(data)

        def write(self, path, data, offset, fh):
            if not self.rw:
                return 0

            if offset + len(data) > self.files[path]['st_size']:
                return b''

            file_offset = 0
            if 'offset' in self.files[path]:
                file_offset = self.files[path]['offset']

            with NamedTemporaryFile('rb+', buffering=0) as f_write:
                f_write.write(data)
                self.da_handler.da_wo(start=file_offset + offset, length=len(data), filename=f_write.name,
                                      parttype=None)
            return len(data)

        def getattr(self, path, fh=None):
            if not self.rw:
                self.files[path]['st_mode'] &= ~0o222
            return self.files[path]

except ImportError:
    print('fuse library not installed')

    class MtkDaFS():
        def __init__(self, da_handler, rw=False):
            pass
    pass
