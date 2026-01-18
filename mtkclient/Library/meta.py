#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import hashlib
import time
import sys
import logging
from enum import Enum
from mtkclient.Library.gui_utils import LogBase, logsetup


class META(metaclass=LogBase):
    class Mode(Enum):
        FASTBOOT = b"FASTBOOT"  # fastboot mode
        META = b"METAMETA"  # MAUI META mode
        EMETA = b"ADVEMETA"  # Advanced META mode
        FACT = b"FACTFACT"  # Factory menu
        ATE = b"FACTORYM"  # ATE Signaling Test
        READY = b"READY"
        ATNBOOT = b"AT+NBOOT"

    def __init__(self, mtk, loglevel=logging.INFO):
        self.mtk = mtk
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.gcpu = None
        self.config = mtk.config
        self.display = True
        self.rbyte = self.mtk.port.rbyte
        self.rword = self.mtk.port.rword
        self.rdword = self.mtk.port.rdword
        self.usbread = self.mtk.port.usbread
        self.usbwrite = self.mtk.port.usbwrite
        self.echo = self.mtk.port.echo
        self.sendcmd = self.mtk.port.mtk_cmd

    def init(self, metamode: bytes, maxtries=None, display=True):
        if not display:
            self.info("Status: Waiting for PreLoader VCOM, please reconnect mobile to preloader mode")
        else:
            self.info("Status: Waiting for PreLoader VCOM, please connect mobile")
        counter = 0
        loop = 0
        cdc = self.mtk.port.cdc
        while not cdc.connected:
            try:
                if maxtries is not None and counter == maxtries:
                    break
                cdc.connected = cdc.connect()
                if cdc.connected and cdc.pid == 0x2000:
                    counter += 1
                    ep_out = cdc.EP_OUT.write
                    ep_in = cdc.EP_IN.read
                    maxinsize = cdc.EP_IN.wMaxPacketSize
                    while True:
                        try:
                            resp = bytearray(ep_in(maxinsize))
                        except Exception:
                            break
                        if resp == b"READY":
                            ep_out(metamode, len(metamode))
                            while resp == b"READY":
                                resp = bytearray(ep_in(maxinsize))
                            if resp in [b"METASLA"]:
                                ep_out(b"SLASTART")
                                resp = bytearray(ep_in(maxinsize))
                                secret = b""
                                if b"RANDOM" in resp:
                                    if b"EXT" in resp:
                                        vendor = "tecno"
                                    else:
                                        vendor = "infinix"
                                    if b"SHA" in resp:
                                        # b"RANDOM"+8925B1F2+b"SHA"+03000000+0000000000
                                        timeval = resp[6:6 + 4]
                                        keyid = int.from_bytes(resp[0xD:0xD + 4], 'little')
                                        if vendor == "infinix":
                                            secret = bytearray(
                                                [0x7C, 0x34, 0xE1, 0x89, 0x12, 0xE1, 0xCD, 0x3D, 0x56, 0x31, 0xAD, 0xB2,
                                                 0x24, 0x76, 0xD3, 0x12, 0x34, 0xE2, 0xCA, 0xFD, 0x13, 0x12, 0x3D, 0x2B,
                                                 0x3B, 0x13, 0xE1, 0x57, 0x22, 0xAD, 0xC1, 0x1D, 0x3D, 0x34, 0xFD, 0x3D,
                                                 0x1A, 0x57, 0x46, 0x1A, 0x35, 0x13, 0xC4, 0xAF, 0x5A, 0x86, 0x22, 0x45,
                                                 0x9D, 0x3D, 0xD1, 0x46, 0x72, 0x41, 0x4F, 0xAD, 0x46, 0xAD, 0x53, 0x11,
                                                 0xC2, 0x3B, 0x3D, 0x2D, 0x1A, 0x2F, 0x3D, 0xFA, 0xDF, 0x35, 0x57, 0x24,
                                                 0xA7, 0x4D, 0x5E, 0x4F, 0x34, 0xD3, 0x4F, 0x2D, 0xDF, 0x1F, 0x13, 0xD3,
                                                 0xB2, 0x91, 0x41, 0x3D, 0x4F, 0xD1, 0x5D, 0x91, 0xFD, 0x2E, 0x4D, 0x6F,
                                                 0x3D, 0x41, 0x34, 0x7F, 0x45, 0xF3, 0x8A, 0x26, 0x1A, 0x33, 0x4F, 0x3E,
                                                 0x5E, 0x64, 0x36, 0x8A, 0xD1, 0xF6, 0x9F, 0x35, 0x6A, 0x96, 0x2A,
                                                 0x5D])
                                            key = secret[(0xC * keyid):(0xC * keyid) + 0xC]
                                            ep_out(hashlib.sha256(timeval + key).digest())
                                    else:
                                        if vendor == "infinix":
                                            secret = b"\xC4\x92\xAD\x3A\x61\xF9\xCE\xC3\x13\x7F\xA9\xCB"
                                        elif vendor in ["tecno", "itel"]:
                                            secret = b"\x4C\xEE\xCB\x1C\xB4\xB1\x1D\x2B\x43\x18\x84\x3F"
                                        # b"RANDOM"+41080000+000000000000000000000000
                                        timeval = resp[6:6 + 4]
                                        ep_out(hashlib.md5(timeval + secret).digest())
                                    resp = bytearray(ep_in(maxinsize))
                                    if resp == b"ATEM0001":
                                        ep_out(bytes.fromhex("040000000100000003000000"))
                                        resp = bytearray(ep_in(maxinsize))
                                        if resp == b"ATEM0002":
                                            ep_out(bytes.fromhex("06000000010000000300000001000000"))
                                            resp = bytearray(ep_in(maxinsize))
                                            if resp == b"ATEMATEX":
                                                ep_out(b"DISCONNECT")
                                                return True
                            if resp in [b"ATEMEVDX", b"TOOBTSAF", b"ATEMATEM", b"TCAFTCAF", b"MYROTCAF"]:
                                if resp == b"ATEMATEM":
                                    ep_out(b"\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0")
                                    ep_out(b"\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0")
                                    ep_out(b"\x06\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0\x00\x80\x00\x00")
                                    # INFO =
                                    ep_in(13)  # !READYATEM
                                ep_out(b"DISCONNECT")
                                return True
                            self.warning(resp)
                else:
                    if cdc.connected:
                        cdc.close()
                        cdc.connected = False
                    if loop == 5:
                        sys.stdout.write('\n')
                        self.info("Hint:\n\nPower off the phone before connecting.\n" +
                                  "For preloader mode, don't press any hw button and connect usb.\n")
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

    def init_wdg(self, display=True):
        if display:
            self.info("Status: Waiting for PreLoader VCOM, please reconnect mobile/iot device to brom mode")
            self.config.set_gui_status(self.config.tr("Status: Waiting for connection"))
        res = False
        maxtries = 100
        tries = 0
        while not res and tries < 1000:
            if self.mtk.serialportname:
                res = self.mtk.port.serial_handshake(maxtries=maxtries)
            else:
                res = self.mtk.port.handshake(maxtries=maxtries)
            if not res:
                if display:
                    self.error("Status: Handshake failed, retrying...")
                    self.config.set_gui_status(self.config.tr("Status: Handshake failed, retrying..."))
                self.mtk.port.close()
                tries += 1
        if tries == 1000:
            return False

        # Get HW code
        if not self.echo(0xFD):  # 0xFD
            if not self.echo(0xFD):
                self.error("Sync error. Please power off the device and retry.")
                self.config.set_gui_status(self.config.tr("Sync error. Please power off the device and retry."))
            return False
        else:
            val = self.rdword()
            self.config.hwcode = (val >> 16) & 0xFFFF
            self.config.hwver = val & 0xFFFF
            self.config.init_hwcode(self.config.hwcode)

        # Disable watchdog
        # self.mtk.preloader.write32(0x10007000, 0x22000064)
        wdg_addr, value = self.config.get_watchdog_addr()
        self.mtk.preloader.setreg_disablewatchdogtimer(self.mtk.config.hwcode, self.mtk.config.hwver)
        # Set meta mode
        self.mtk.preloader.brom_register_access(mode=3, address=0, length=1, data=b"\x01")
        self.mtk.preloader.brom_register_access(mode=2, address=0, length=1)
        time.sleep(0.2)
        # Enable watchdog, reset phone
        self.mtk.preloader.write32(wdg_addr + 0x14, 0x00001209)
        time.sleep(1)
        return True
