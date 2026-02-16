#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025
import inspect
import traceback
import logging
import os
from binascii import hexlify
from mtkclient.Library.gui_utils import LogBase
from mtkclient.Library.utils import unpack


class DeviceClass(metaclass=LogBase):

    def __init__(self, loglevel=logging.INFO, portconfig=None, devclass=-1):
        self.connected = False
        self.timeout = 1000
        self.maxsize = 512
        self.vid = None
        self.pid = None
        self.stopbits = None
        self.databits = None
        self.parity = None
        self.baudrate = None
        self.configuration = None
        self.device = None
        self.devclass = devclass
        self.loglevel = loglevel
        self.xmlread = True
        self.portconfig = portconfig
        self.portname = None
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.debug = self.__logger.debug
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)

    def get_read_packetsize(self):
        raise NotImplementedError()

    def get_write_packetsize(self):
        raise NotImplementedError()

    def connect(self, ep_in=-1, ep_out=-1):
        raise NotImplementedError()

    def setportname(self, portname: str):
        raise NotImplementedError()

    def set_fast_mode(self, enabled: bool):
        raise NotImplementedError

    def close(self, reset=False):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def detectdevices(self):
        raise NotImplementedError()

    def get_interface_count(self):
        raise NotImplementedError()

    def set_line_coding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        raise NotImplementedError()

    def setbreak(self):
        raise NotImplementedError()

    def setcontrollinestate(self, rts=None, dtr=None, is_ftdi=False):
        raise NotImplementedError()

    def write(self, command, pktsize=None):
        raise NotImplementedError()

    def usbwrite(self, data, pktsize=None):
        raise NotImplementedError()

    def usbread(self, resplen=None, timeout=0, w_max_packet_size=None):
        raise NotImplementedError()

    def usbxmlread(self, maxtimeout=100):
        raise NotImplementedError()

    def ctrl_transfer(self, bm_request_type, b_request, w_value, w_index, data_or_w_length):
        raise NotImplementedError()

    def usbreadwrite(self, data, resplen):
        raise NotImplementedError()

    def read(self, length=None, timeout=-1):
        if timeout == -1:
            timeout = self.timeout
        if length is None:
            length = self.maxsize
        return self.usbread(length, timeout)

    def rdword(self, count=1, little=False, direct=False):
        rev = "<" if little else ">"
        value = self.usbread(4 * count)
        if direct:
            return value
        data = unpack(rev + "I" * count, value)
        if count == 1:
            return data[0]
        return data

    def rword(self, count=1, little=False):
        rev = "<" if little else ">"
        value = self.usbread(2 * count)
        data = unpack(rev + "H" * count, value)
        if count == 1:
            return data[0]
        return data

    def rbyte(self, count=1):
        return self.usbread(count)

    def verify_data(self, data, pre="RX:"):
        if self.__logger.level == logging.DEBUG:
            frame = inspect.currentframe()
            stack_trace = traceback.format_stack(frame)
            td = []
            for trace in stack_trace:
                if "verify_data" not in trace and "Port" not in trace:
                    td.append(trace)
            self.debug(td[:-1])

        if isinstance(data, bytes) or isinstance(data, bytearray):
            if data[:5] == b"<?xml":
                try:
                    rdata = b""
                    for line in data.split(b"\n"):
                        try:
                            self.debug(pre + line.decode('utf-8'))
                            rdata += line + b"\n"
                        except Exception:
                            v = hexlify(line)
                            self.debug(pre + v.decode('utf-8'))
                    return rdata
                except Exception as err:
                    self.debug(str(err))
                    pass
            if logging.DEBUG >= self.__logger.level:
                self.debug(pre + hexlify(data).decode('utf-8'))
        else:
            if logging.DEBUG >= self.__logger.level:
                self.debug(pre + hexlify(data).decode('utf-8'))
        return data
