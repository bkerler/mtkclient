import unittest

from mtkclient.Library.DA.mtk_daloader import DAloader


class DAloaderStateTest(unittest.TestCase):
    def test_decodes_saved_meid(self):
        state = {"meid": "00112233445566778899aabbccddeeff"}

        meid = DAloader._get_state_bytes(state, "meid")

        self.assertEqual(meid, bytes.fromhex(state["meid"]))

    def test_missing_meid_remains_unset(self):
        self.assertIsNone(DAloader._get_state_bytes({}, "meid"))

    def test_null_meid_remains_unset(self):
        self.assertIsNone(DAloader._get_state_bytes({"meid": None}, "meid"))


if __name__ == "__main__":
    unittest.main()
