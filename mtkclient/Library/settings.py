import json
import os.path
from binascii import hexlify


class HwParam:
    paramsetting = None
    hwcode = None
    appid = b""

    def __init__(self, config, meid: str, path: str = "logs"):
        self.config = config
        self.paramfile = "hwparam.json"
        self.config.hwparam_path = path
        self.appid = b""
        if isinstance(meid, bytearray) or isinstance(meid, bytes):
            meid = hexlify(meid).decode('utf-8')
        if meid is None:
            self.paramsetting = {}
        else:
            self.paramsetting = {}
            if os.path.exists(os.path.join(path, self.paramfile)):
                try:
                    tmp = json.loads(open(os.path.join(path, self.paramfile), "r").read())
                    if tmp["meid"] == meid:
                        self.paramsetting = tmp
                    else:
                        self.paramsetting = {}
                        self.paramsetting["meid"] = meid
                except Exception:
                    # json file invalid, load nothing.
                    pass

    def loadsetting(self, key: str):
        if self.paramsetting is not None:
            if key in self.paramsetting:
                return self.paramsetting[key]
        return None

    def writesetting(self, key: str, value: str):
        if self.paramsetting is not None:
            self.paramsetting[key] = value
            self.write_json()

    def write_json(self):
        if self.paramsetting is not None:
            if not os.path.exists(self.config.hwparam_path):
                os.mkdir(self.config.hwparam_path)
            open(os.path.join(self.config.hwparam_path, self.paramfile), "w").write(json.dumps(self.paramsetting))
