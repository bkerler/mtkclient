#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 GPLv3 License
import os
import sys
import logging
import time
from binascii import hexlify
from struct import pack
from mtkclient.Library.utils import LogBase, logsetup
from mtkclient.Library.Connection.usblib import UsbClass
from mtkclient.Library.Connection.seriallib import SerialClass


class Port(metaclass=LogBase):
    class DeviceClass:
        vid = 0
        pid = 0

        def __init__(self, vid, pid):
            self.vid = vid
            self.pid = pid

    def __init__(self, mtk, portconfig, serialportname: str = None, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, 
                                                                                  loglevel, mtk.config.gui)
        self.config = mtk.config
        self.mtk = mtk
        self.serialportname = None
        if serialportname is not None:
            self.cdc = SerialClass(portconfig=portconfig, loglevel=loglevel, devclass=10)
            self.cdc.setportname(serialportname)
        else:
            self.cdc = UsbClass(portconfig=portconfig, loglevel=loglevel, devclass=10)
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

    def run_serial_handshake(self):
        try:  # Support for serial port where ep_out is unknown
            if hasattr(self.cdc, 'ep_out'):
                ep_out = self.cdc.EP_OUT.write
                # maxinsize = self.cdc.ep_in.wMaxPacketSize
            else:
                ep_out = self.cdc.write
        except Exception:
            ep_out = self.cdc.write
        try:
            if hasattr(self.cdc, 'ep_in'):
                ep_in = self.cdc.EP_IN.read
            else:
                ep_in = self.cdc.read
        except Exception:
            ep_in = self.cdc.read

        i = 0
        startcmd = b"\xa0\x0a\x50\x05"
        length = len(startcmd)
        try:
            while i < length:
                if ep_out(int.to_bytes(startcmd[i], 1, 'little')):
                    v = ep_in(1, timeout=20)  # Do not wait 1 sec, bootloader is only active for 0.3 sec.
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

    def serial_handshake(self, maxtries=None, loop=0):
        counter = 0
        if not self.cdc.connected:
            self.cdc.connected = self.cdc.connect()
        while 1:  # Workaround for serial port
            try:
                if not self.cdc.connected:
                    self.cdc.connected = self.cdc.connect()
                if maxtries is not None and counter == maxtries:
                    break
                counter += 1
                # self.cdc.connected = self.cdc.connect()
                if self.cdc.connected and self.run_serial_handshake():
                    self.info("Handshake successful.")
                    return True
                else:
                    if loop == 5:
                        sys.stdout.write('\n')
                        self.info("Hint:\n\nPower off the phone before connecting.\n" +
                                  "For brom mode, press and hold vol up, vol dwn, or all hw buttons and " +
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
                    time.sleep(0.1)
                    sys.stdout.flush()

            except Exception as serr:
                print(f"Handshake: {str(serr)}")
                if "access denied" in str(serr):
                    self.warning(str(serr))
                self.debug(str(serr))
                pass
        return False

 #   def run_handshake(self):
        
            
       

    def handshake(self, maxtries=None, loop=0):
        counter = 0
        while not self.cdc.connected:
            try:
                if maxtries is not None and counter == maxtries:
                    break
                counter += 1
                    self.cdc.connect() 
                    ep_out = self.cdc.EP_OUT.write
                    ep_in = self.cdc.EP_IN.read
                    maxinsize = self.cdc.EP_IN.wMaxPacketSize

                    i = 0
                    startcmd = b"\xa0\x0a\x50\x05"
                    length = len(startcmd)
                    # On preloader, send 0xa0 first
                    if self.cdc.pid!=0x3:
                        ep_out(startcmd[0:1])
                    try:
                      while i < length:
                        if ep_out(startcmd[i:i+1]):
                            if ep_in(maxinsize)[-1] == ~(startcmd[i]) & 0xFF:
                                i += 1
                            else:
                                i = 0
                            
                        
                      self.info("Device detected :)")
                      return True
                    
                    except Exception as serr:
                     self.debug(str(serr))
                     time.sleep(0.005)
                     return False
                

            except Exception as serr:
                if "access denied" in str(serr):
                    self.warning(str(serr))
                # self.debug(str(serr))
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
                    self.error(f"Cmd error :{hexlify(cmdrsp).decode('utf-8')}")
                    return -1
                if bytestoread > 0:
                    resp = self.usbread(bytestoread)
                return resp
        else:
            self.warning(f"Couldn't send :{hexlify(value).decode('utf-8')}")
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
