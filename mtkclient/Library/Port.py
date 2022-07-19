#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021 GPLv3 License
import os
import sys
import logging
import time
from binascii import hexlify
from struct import pack
from mtkclient.Library.utils import LogBase, logsetup
from mtkclient.Library.Connection.usblib import usb_class
from mtkclient.Library.Connection.seriallib import serial_class

class Port(metaclass=LogBase):
    class deviceclass:
        vid = 0
        pid = 0

        def __init__(self, vid, pid):
            self.vid = vid
            self.pid = pid

    def __init__(self, mtk, portconfig, serialportname:str=None, loglevel=logging.INFO):
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.config = mtk.config
        self.mtk = mtk
        self.serialportname = None
        if serialportname is not None:
            self.cdc = serial_class(portconfig=portconfig, loglevel=loglevel, devclass=10)
            self.cdc.setportname(serialportname)
        else:
            self.cdc = usb_class(portconfig=portconfig, loglevel=loglevel, devclass=10)
        self.usbread = self.cdc.usbread
        self.usbwrite = self.cdc.usbwrite
        self.close = self.cdc.close
        self.rdword = self.cdc.rdword
        self.rword = self.cdc.rword
        self.rbyte = self.cdc.rbyte
        self.detectusbdevices = self.cdc.detectdevices
        self.usbreadwrite = self.cdc.usbreadwrite

        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def run_handshake(self):
        EP_OUT = self.cdc.EP_OUT.write
        EP_IN = self.cdc.EP_IN.read
        maxinsize = self.cdc.EP_IN.wMaxPacketSize

        i = 0
        startcmd = b"\xa0\x0a\x50\x05"
        length = len(startcmd)
        try:
            while i < length:
                if EP_OUT(int.to_bytes(startcmd[i], 1, 'little')):
                    v = EP_IN(maxinsize)
                    if len(v) == 1 and v[0] == ~(startcmd[i]) & 0xFF:
                        i += 1
                    else:
                        i = 0
            self.info("Device detected :)")
            return True
        except Exception as serr:
            self.debug(str(serr))
            time.sleep(0.005)
        return False

    def handshake(self, maxtries=None, loop=0):
        counter = 0

        while not self.cdc.connected:
            try:
                if maxtries is not None and counter == maxtries:
                    break
                counter += 1
                self.cdc.connected = self.cdc.connect()
                if self.cdc.connected and self.run_handshake():
                    return True
                else:
                    if loop == 5:
                        sys.stdout.write('\n')
                        self.info("Hint:\n\nPower off the phone before connecting.\n" + \
                                  "For brom mode, press and hold vol up, vol dwn, or all hw buttons and " + \
                                  "connect usb.\n" +
                                  "For preloader mode, don't press any hw button and connect usb.\n"
                                  "If it is already connected and on, hold power for 10 seconds to reset.\n")
                        sys.stdout.write('\n')
                    if loop >= 10:
                        sys.stdout.write('.')
                    if loop >= 20:
                        sys.stdout.write('\n')
                        loop = 0
                    loop += 1
                    time.sleep(0.3)
                    sys.stdout.flush()


            except Exception as serr:
                if "access denied" in str(serr):
                    self.warning(str(serr))
                self.debug(str(serr))
                pass
        return False

    def mtk_cmd(self, value, bytestoread=0, nocmd=False):
        resp = b""
        dlen = len(value)
        wr = self.usbwrite(value)
        time.sleep(0.05)
        if wr:
            if nocmd:
                cmdrsp = self.usbread(bytestoread)
                return cmdrsp
            else:
                cmdrsp = self.usbread(dlen)
                if cmdrsp[0] is not value[0]:
                    self.error("Cmd error :" + hexlify(cmdrsp).decode('utf-8'))
                    return -1
                if bytestoread > 0:
                    resp = self.usbread(bytestoread)
                return resp
        else:
            self.warning("Couldn't send :" + hexlify(value).decode('utf-8'))
            return resp

    def echo(self, data):
        if isinstance(data, int):
            data = pack(">I", data)
        if isinstance(data, bytes):
            data = [data]
        for val in data:
            self.usbwrite(val)
            tmp = self.usbread(len(val), maxtimeout=0)
            # print(hexlify(tmp))
            if val != tmp:
                return False
        return True
