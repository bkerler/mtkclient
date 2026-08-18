#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Android sparse-image reader/expander.

Firmware images for large partitions (super, userdata, ...) are usually
distributed in the Android *sparse* format (magic 0xED26FF3A), not as raw
filesystem images. A sparse file is a header plus a list of chunks: RAW (data
follows), FILL (a repeated 4-byte value), DONT_CARE (a hole -- nothing to
write), and CRC32. Its on-disk size has nothing to do with the size of the
partition it expands to (e.g. a 2.4 MB userdata.img expands to 3.2 GB).

Writing a sparse file raw to a partition corrupts it -- the chunk headers land
inside the filesystem and the holes are never skipped. SP Flash Tool expands
sparse images (its DA has an UNSPARSE engine); we expand them on the host and
stream only the real regions to the flash, seeking over DONT_CARE holes.
"""
from struct import unpack

SPARSE_MAGIC = 0xED26FF3A

CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4

_STREAM_SLICE = 8 * 1024 * 1024  # cap in-memory/write size per flash call


def is_sparse(data: bytes) -> bool:
    """True if the first 4 bytes are the Android sparse magic."""
    return len(data) >= 4 and unpack("<I", data[:4])[0] == SPARSE_MAGIC


def is_sparse_file(path: str) -> bool:
    with open(path, "rb") as rf:
        return is_sparse(rf.read(4))


class SparseImage:
    """Streams the real (non-hole) regions of an Android sparse file.

    Usage:
        with SparseImage(path) as img:
            for offset, data in img.regions():
                write(base_addr + offset, data)
    """

    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "rb")
        hdr = self.fh.read(28)
        if not is_sparse(hdr):
            self.fh.close()
            raise ValueError(f"{path} is not an Android sparse image")
        (magic, self.major, self.minor, self.file_hdr_sz, self.chunk_hdr_sz,
         self.blk_sz, self.total_blks, self.total_chunks,
         self.image_checksum) = unpack("<IHHHHIIII", hdr)
        if self.major != 1:
            self.fh.close()
            raise ValueError(f"{path}: unsupported sparse version {self.major}.{self.minor}")
        # skip any extra header bytes the writer declared
        if self.file_hdr_sz > 28:
            self.fh.read(self.file_hdr_sz - 28)

    @property
    def expanded_size(self) -> int:
        return self.total_blks * self.blk_sz

    def regions(self):
        """Yield (dest_offset, data) for every RAW/FILL region, in order.

        DONT_CARE chunks advance dest_offset without yielding (holes). Large
        chunks are split into <= _STREAM_SLICE pieces so nothing huge is held
        in memory. dest_offset is always a multiple of blk_sz.
        """
        dest = 0
        for _ in range(self.total_chunks):
            chunk_hdr = self.fh.read(self.chunk_hdr_sz)
            if len(chunk_hdr) < 12:
                raise ValueError(f"{self.path}: truncated chunk header")
            chunk_type, _res, chunk_blks, total_sz = unpack("<HHII", chunk_hdr[:12])
            if self.chunk_hdr_sz > 12:
                self.fh.read(self.chunk_hdr_sz - 12)
            out_len = chunk_blks * self.blk_sz
            body = total_sz - self.chunk_hdr_sz

            if chunk_type == CHUNK_RAW:
                if body != out_len:
                    raise ValueError(f"{self.path}: RAW chunk body {body} != {out_len}")
                remaining = out_len
                while remaining > 0:
                    n = min(remaining, _STREAM_SLICE)
                    data = self.fh.read(n)
                    if len(data) != n:
                        raise ValueError(f"{self.path}: truncated RAW chunk")
                    yield dest, data
                    dest += n
                    remaining -= n
            elif chunk_type == CHUNK_FILL:
                fill = self.fh.read(4)
                if len(fill) != 4:
                    raise ValueError(f"{self.path}: truncated FILL chunk")
                if fill == b"\x00\x00\x00\x00":
                    # a fill of zero is effectively a hole; skip it
                    dest += out_len
                    continue
                remaining = out_len
                while remaining > 0:
                    n = min(remaining, _STREAM_SLICE)
                    yield dest, (fill * (n // 4))
                    dest += n
                    remaining -= n
            elif chunk_type == CHUNK_DONT_CARE:
                dest += out_len            # hole: nothing to write
            elif chunk_type == CHUNK_CRC32:
                self.fh.read(body)         # checksum chunk: consume, ignore
            else:
                raise ValueError(f"{self.path}: unknown sparse chunk type {chunk_type:#x}")

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
