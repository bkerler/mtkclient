#!/usr/bin/env python3
import sys
import hashlib
from mtkclient.Library.utils import find_binary

patches = [
    ("B3F5807F01D1", "B3F5807F01D14FF000004FF000007047"),  # rsa_verify / usbdl_vfy_da
    ("B3F5807F04BF4FF4807305F011B84FF0FF307047", "B3F5807F04BF4FF480734FF000004FF000007047"),
    # rsa_verify / usbdl_vfy_da
    ("2DE9F746802B", "4FF000007047"),  # rsa_verify / usbdl_vfy_da
    ("802B2DE9", "4FF000007047"),
    ("8023BDE8", "4FF000007047"),  # DA verify fail
    ("800053E3F344", "0000A0E31EFF2FE1")
]


def patch_preloader_security(data):
    if data[:4] != b"\x4D\x4D\x4D\x01":
        return data
    patched = False
    for patchval in patches:
        pattern = bytes.fromhex(patchval[0])
        idx = data.find(pattern)
        if idx != -1:
            patch = bytes.fromhex(patchval[1])
            data[idx:idx + len(patch)] = patch
            patched = True
            break
    if patched:
        # with open(sys.argv[1]+".patched","wb") as wf:
        #    wf.write(data)
        #    print("Patched !")
        print("Patched preloader security")
    else:
        print(f"Failed to patch preloader security: {sys.argv[1]}")
    return data


def patch_da2_legacy(da2):
    # open("da2.bin","wb").write(da2)
    da2patched = bytearray(da2)
    # Patch security
    check_addr = find_binary(da2, b"\x08\xB5\x4F\xF4\x50\x42\xA0\xF1\x81\x53")
    if check_addr is not None:
        da2patched[check_addr:check_addr + 4] = b"\x08\xB5\x08\xBD"
        print("Patched preloader security")
    else:
        print(f"Failed to patch preloader security: {sys.argv[1]}")
    return da2patched


def fix_hash(da1, da2, hashpos, hashmode):
    da1 = bytearray(da1)
    dahash = None
    if hashmode == 0:
        dahash = hashlib.md5(da2).digest()
    if hashmode == 1:
        dahash = hashlib.sha1(da2).digest()
    elif hashmode == 2:
        dahash = hashlib.sha256(da2).digest()
    da1[hashpos:hashpos + len(dahash)] = dahash
    return da1


def compute_hash_pos(da1, da2):
    hashdigestmd5 = hashlib.md5(da2).digest()
    hashdigest = hashlib.sha1(da2).digest()
    hashdigest256 = hashlib.sha256(da2).digest()
    idx = da1.find(hashdigestmd5)
    hashmode = 0
    if idx == -1:
        idx = da1.find(hashdigest)
        hashmode = 1
    if idx == -1:
        idx = da1.find(hashdigest256)
        hashmode = 2
    if idx != -1:
        return idx, hashmode
    return None, None


def main():
    """
    with open(sys.argv[1],"rb") as rf:
        data=bytearray(rf.read())
        data=patch_preloader_security(data)
    """
    da1 = open("loaders/6735_200000MTK_AllInOne_DA_5.2136.bin", "rb").read()
    da2 = open("loaders/6735_40000000MTK_AllInOne_DA_5.2136.bin", "rb").read()
    hp, hm = compute_hash_pos(da1, da2[:-0x100])
    da2 = patch_da2_legacy(da2)
    fix_hash(da1, da2, hp, hm)


if __name__ == "__main__":
    main()
