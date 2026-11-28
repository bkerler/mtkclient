#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool V6
# Licensed under GPLv3 License
#
# Load-image validation for mtkclient (imageChecker port).
#
# Ported from SP Flash Tool V6 (see begonia-kernel-research/
# spft-decompile-2026-11-24.md, section 5.6 "imageChecker"):
#  - imageChecker.dll / libimagechecker.1.0.0.so, called through the flash.dll
#    export flashtool_images_checker_verify before any firmware download
#  - ConsoleMode::ConsoleModeRunner::imageChksumVerify /
#    AsyncFlashXMLLoader::imageChksumVerify ("Begin verify load images
#    checksum", "verify load images checksum done!", "image checksum mismatch")
#  - download feedback wording (GET-DOWNLOADED-IMAGE-FEEDBACK): "Downloaded
#    Checksum Error/Passed: Partition[%s], image file[%s], ..."
#  - SPFT layout check CDefaultRom::CheckPmtLayout: "PMT no <%s>!"
#
# The checker is deliberately device-free: it validates the images the host is
# about to flash against the partition layout (from a parsed scatter) BEFORE a
# DA connection is established - the same pre-flight role imageChecker.dll
# plays in SPFT V6. Checksum verification is layered on top via ChksumRule
# (Library.chksum); images without a rule entry are skipped, exactly like the
# SPFT flow ("skip chksum for rom(%s).").
import logging
import os

from mtkclient.Library.gui_utils import LogBase, logsetup


class ImageCheckStatus:
    """Per-image verdict (mirrors the SPFT download feedback wording)."""
    PASS = "PASS"    # "Downloaded Checksum Passed" / image fits its partition
    SKIP = "SKIP"    # "Skipped protected partition checksum compare" / no rule
    FAIL = "FAIL"    # "Downloaded Checksum Error" / layout or size violation


class ImageCheckItem:
    """One validated image: partition name, image path, verdict and detail."""

    def __init__(self, partition: str, image: str, status: str, detail: str = ""):
        self.partition = partition
        self.image = image
        self.status = status
        self.detail = detail

    def __repr__(self):
        return f"ImageCheckItem({self.partition!r}, {self.image!r}, {self.status}, {self.detail!r})"


def _attr(obj, name, default=None):
    """Duck-typed attribute access: ScatterPartition, gpt.partf or plain dicts."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _part_name(part):
    return str(_attr(part, "partition_name", _attr(part, "name", "")) or "")


def _part_size(part):
    return int(_attr(part, "partition_size", _attr(part, "size", 0)) or 0)


def _part_downloadable(part):
    # scatter 'is_download' flag; GPT-style entries without the flag count as
    # downloadable (they were explicitly requested by the caller)
    return bool(_attr(part, "is_download", True))


class ImageChecker(metaclass=LogBase):
    """
    Validates load images against a partition layout before flashing:
      - the target partition must exist in the layout ("PMT no <%s>!")
      - the partition must be downloadable
      - the image file must exist and be non-empty
      - the image must fit the partition
      - optionally the image checksum must match its ChksumRule entry
    """

    def __init__(self, partitions=None, images=None, chksum_rule=None,
                 loglevel=logging.INFO):
        self.partitions = list(partitions or [])
        self.images = dict(images or {})
        self.chksum_rule = chksum_rule
        self.__logger, self.info, self.debug, self.warning, self.error = \
            logsetup(self, self.__logger, loglevel)

    def _find_partition(self, partition_name: str):
        want = str(partition_name or "").lower()
        for part in self.partitions:
            if _part_name(part).lower() == want:
                return part
        return None

    def verify_images(self) -> list:
        """
        Validate every requested image. Returns one ImageCheckItem per image;
        the overall run is a pass when no item FAILED.
        """
        items = []
        for partition_name, image_path in self.images.items():
            items.append(self._verify_one(partition_name, image_path))
        return items

    def verify(self) -> bool:
        """
        Full pre-flight check (flashtool_images_checker_verify flow). Logs the
        SPFT-style summary and returns True when no image failed.
        """
        self.info("Begin verify load images checksum")
        items = self.verify_images()
        failed = [item for item in items if item.status == ImageCheckStatus.FAIL]
        for item in failed:
            self.error(f"Partition[{item.partition}], image file[{item.image}]: "
                       f"{item.detail}")
        if failed:
            self.error(f"image check failed for {len(failed)}/{len(items)} image(s)")
            return False
        self.info("verify load images checksum done!")
        return True

    def _verify_one(self, partition_name: str, image_path: str) -> ImageCheckItem:
        part = self._find_partition(partition_name)
        if part is None:
            # SPFT CDefaultRom::CheckPmtLayout: "PMT no <%s>!"
            return ImageCheckItem(partition_name, image_path, ImageCheckStatus.FAIL,
                                  f"PMT no <{partition_name}>! "
                                  "(partition not found in the layout)")
        if not _part_downloadable(part):
            return ImageCheckItem(partition_name, image_path, ImageCheckStatus.SKIP,
                                  f"partition {partition_name} is not a download "
                                  "partition (scatter is_download=FALSE)")
        if not os.path.exists(image_path):
            return ImageCheckItem(partition_name, image_path, ImageCheckStatus.FAIL,
                                  f"image file not found: {image_path}")
        size = os.stat(image_path).st_size
        part_size = _part_size(part)
        if size == 0:
            return ImageCheckItem(partition_name, image_path, ImageCheckStatus.FAIL,
                                  "image file is empty")
        if part_size and size > part_size:
            return ImageCheckItem(partition_name, image_path, ImageCheckStatus.FAIL,
                                  f"image does not fit partition {partition_name}: "
                                  f"{size} bytes > {part_size} bytes")
        status, detail = self._verify_chksum(partition_name, image_path, size, part_size)
        return ImageCheckItem(partition_name, image_path, status, detail)

    def _verify_chksum(self, partition_name: str, image_path: str,
                       size: int, part_size: int) -> "tuple[str, str]":
        detail = f"{size} bytes fit partition ({part_size} bytes)"
        if self.chksum_rule is None:
            return ImageCheckStatus.PASS, detail
        expected = self.chksum_rule.QueryChksumByImageName(os.path.basename(image_path))
        if expected is None:
            # SPFT AppCore::VerifyImageChksum: "skip chksum for rom(%s)."
            return ImageCheckStatus.SKIP, f"skip chksum for rom({image_path})."
        with open(image_path, "rb") as rf:
            data = rf.read()
        if not self.chksum_rule.verify_image(os.path.basename(image_path), data):
            # SPFT imageChksumVerify: "image checksum mismatch"
            return ImageCheckStatus.FAIL, f"image checksum mismatch: {image_path}"
        return ImageCheckStatus.PASS, (detail +
                                       f", checksum OK (0x{expected:08x})")


def images_checker_verify(partitions=None, images=None, chksum_rule=None) -> bool:
    """
    flash.dll export namesake (flashtool_images_checker_verify): validate the
    load images against the layout. True when every image passes.
    """
    return ImageChecker(partitions, images, chksum_rule=chksum_rule).verify()
