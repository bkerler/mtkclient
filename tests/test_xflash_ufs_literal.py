import unittest
from struct import pack

from mtkclient.Library.DA.xflash.extension.xflash import XFlashExt


class UfsHbaLiteralTest(unittest.TestCase):
    def test_reads_literal_after_alignment_nop(self):
        function_return = bytes.fromhex("20 46 0d b0 bd e8 f0 83")
        data = b"\xAA\xAA" + function_return + b"\x00\xBF" + pack("<I", 0x40066CD0)

        value = XFlashExt._read_ufs_hba_literal(data, 2)

        self.assertEqual(value, 0x40066CD0)

    def test_reads_literal_without_alignment_nop(self):
        function_return = bytes.fromhex("20 46 0d b0 bd e8 f0 83")
        data = function_return + pack("<I", 0x40123454)

        value = XFlashExt._read_ufs_hba_literal(data, 0)

        self.assertEqual(value, 0x40123454)

    def test_rejects_truncated_aligned_literal(self):
        function_return = bytes.fromhex("20 46 0d b0 bd e8 f0 83")
        data = b"\xAA\xAA" + function_return + b"\x00\xBF\xD0\x6C"

        value = XFlashExt._read_ufs_hba_literal(data, 2)

        self.assertIsNone(value)

    def test_rejects_unaligned_literal_without_nop(self):
        function_return = bytes.fromhex("20 46 0d b0 bd e8 f0 83")
        data = b"\xAA\xAA" + function_return + pack("<I", 0x40066CD0)

        value = XFlashExt._read_ufs_hba_literal(data, 2)

        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
