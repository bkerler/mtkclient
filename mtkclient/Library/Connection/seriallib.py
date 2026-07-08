#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025
import time
import sys
import logging
from queue import Queue

from mtkclient.Library.DA.xmlflash.xml_param import max_xml_data_length
import serial
import serial.tools.list_ports
import inspect
from mtkclient.Library.Connection.devicehandler import DeviceClass

if sys.platform != "win32":
    import termios


def _reset_input_buffer():
    return


def _reset_input_buffer_org(self):
    if sys.platform != "win32":
        return termios.tcflush(self.fd, termios.TCIFLUSH)


class SerialClass(DeviceClass):

    def __init__(self, loglevel=logging.INFO, portconfig=None, devclass=-1):
        super().__init__(loglevel, portconfig, devclass)
        self.is_serial = True
        self.device = None
        self.queue = Queue()

    def connect(self, ep_in=-1, ep_out=-1):
        if self.connected:
            self.close()
            self.connected = False

        port = None
        if self.portname not in (None, "", "DETECT"):
            # Port sudah eksplisit (mis. COM4) -> skip scan comports() yang lambat di Windows,
            # langsung coba buka. Preloader cuma hidup ~0.3 detik, tiap ms penting.
            port = self.portname
        else:
            ports = self.detectdevices()
            if ports:
                port = ports[0]
        if port is None:
            return False
        try:
            self.debug("Got port: {}, initializing".format(port))
            # write_timeout: pyserial on Windows never set this before (defaulted to
            # None = block forever). Serial.write() there does WriteFile() then a
            # SYNCHRONOUS GetOverlappedResult(..., True) wait -- a true OS-level
            # block that Python's KeyboardInterrupt cannot preempt (unlike the
            # Python-side time.sleep() loops we bounded for read/flush earlier: those
            # were Ctrl+C-able, this one hardware-hung the whole process). Set it once
            # here, at initial port open (via the constructor, so it's folded into the
            # single _reconfigure_port()/SetCommState call that already happens on
            # open) -- NOT as a later property reassignment, which would risk the same
            # WinError 31 bug #4 was about if done mid-session/right after a burst.
            # 5s per chunk (usbwrite() now actually chunks at get_write_packetsize()
            # bytes -- see write()/usbwrite() below -- so each chunk is <=512 bytes,
            # ~44ms at this baud rate) is generous margin while still failing
            # fast+recoverably instead of hanging forever if the device truly stops
            # responding. write() also never retries-from-the-same-pos after an
            # actual write timeout, since pyserial doesn't tell us how many bytes of
            # that chunk already reached the wire -- see write()'s except block.
            #
            # timeout=2 (read timeout, was 500): this is the ambient default that
            # usbread(resplen=None) below relies on for its own bound, since that one
            # branch deliberately never reassigns self.device.timeout at runtime (see
            # its comment). Setting it once here at construction -- not a later
            # reassignment -- carries none of the WinError 31 risk. Every other read
            # path in this file (usbread's resplen=N branch, usbxmlread) explicitly
            # overrides device.timeout before reading, so this default only matters
            # for that one branch.
            self.device = serial.Serial(port=port, baudrate=115200, bytesize=serial.EIGHTBITS,
                                        parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                                        timeout=2, write_timeout=5,
                                        xonxoff=False, dsrdtr=False, rtscts=False)
            self.portname = port
        except Exception as e:
            self.debug(str(e))
            return False
        self.device._reset_input_buffer = _reset_input_buffer_org
        self.connected = self.device.is_open
        if self.connected:
            return True
        return False

    def setportname(self, portname: str):
        self.portname = portname

    def set_fast_mode(self, enabled):
        pass

    def change_baud(self):
        print("Changing Baudrate")
        self.write(b'\xD2' + b'\x02' + b'\x01')
        self.read(1)
        self.write(b'\x5a')
        # self.read(1)
        self.device.baudrate = 460800
        time.sleep(0.2)
        for i in range(10):
            self.write(b'\xc0')
            self.read(1)
            time.sleep(0.02)
        self.write(b'\x5a')
        self.read(1)

    def close(self, reset=False):
        if self.connected:
            self.device.close()
            del self.device
            self.device = None
            self.connected = False

    def detectdevices(self):
        ids = []
        for port in serial.tools.list_ports.comports():
            for usbid in self.portconfig:
                if "ttyUSB" in port.device or "ttyACM" in port.device:
                    if port.device not in ids:
                        ids.append(port.device)
                elif port.vid == usbid and port.pid in self.portconfig[usbid]:
                    self.info(f"Detected {hex(port.vid)}:{hex(port.pid)} device at: {port.device}")
                    if port.device not in ids:
                        ids.append(port.device)
        return sorted(ids)

    def set_line_coding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        self.device.baudrate = baudrate
        self.device.parity = parity
        self.device.stopbbits = stopbits
        self.device.bytesize = databits
        self.debug("Linecoding set")

    def setbreak(self):
        self.device.send_break()
        self.debug("Break set")

    def setcontrollinestate(self, rts=None, dtr=None, is_ftdi=False):
        self.device.rts = rts
        self.device.dtr = dtr
        self.debug("Linecoding set")

    def write(self, command, pktsize=None):
        if pktsize is None:
            pktsize = 512
        if isinstance(command, str):
            command = bytes(command, 'utf-8')
        pos = 0
        if command == b'':
            try:
                self.device.write(b'')
            except Exception as err:
                error = str(err)
                if "timeout" in error:
                    # time.sleep(0.01)
                    try:
                        self.device.write(b'')
                    except Exception as err:
                        self.debug(str(err))
                        return False
                return True
        else:
            i = 0
            while pos < len(command):
                try:
                    ctr = self.device.write(command[pos:pos + pktsize])
                    if ctr <= 0:
                        self.info(ctr)
                    pos += pktsize
                except Exception as err:
                    error = str(err)
                    self.debug(error)
                    if "timeout" in error.lower():
                        # SerialTimeoutException: pyserial gave up waiting on this
                        # device.write() call, but doesn't tell us how many bytes of
                        # this chunk already reached the wire. Retrying from the same
                        # pos could resend bytes that already went out, corrupting
                        # the stream -- abort instead of retrying.
                        self.error("Write timed out; aborting (retry would risk duplicate bytes on wire)")
                        return False
                    # print("Error while writing")
                    # time.sleep(0.01)
                    i += 1
                    if i == 3:
                        return False
                    pass
        self.verify_data(bytearray(command), "TX:")
        self.device.flushOutput()
        # timeout = 0
        time.sleep(0.005)
        """
        while self.device.in_waiting == 0:
            time.sleep(0.005)
            timeout+=1
            if timeout==10:
                break
        """
        return True

    def read(self, length=None, timeout=-1):
        if timeout == -1:
            timeout = self.timeout
        if length is None:
            length = self.device.in_waiting
            if length == 0:
                return b""
        if self.xmlread:
            if length > self.device.in_waiting:
                length = self.device.in_waiting
        return self.usbread(resplen=length, maxtimeout=timeout)

    def get_device(self):
        return self.device

    def get_read_packetsize(self):
        return 0x200

    def get_write_packetsize(self):
        return 0x200

    def _bounded_flush(self, max_wait=0.05):
        # pyserial's Serial.flush() on Windows is `while self.out_waiting: sleep(0.05)`
        # with NO timeout at all. out_waiting relies on the same Win32
        # ClearCommError/COMSTAT query as in_waiting -- which we already proved
        # unreliable on MTK's proprietary Preloader VCOM driver (never correctly
        # reports queued bytes -- see the usbread resplen=None history). If it never
        # reports 0 on this driver, flush() hangs forever with zero feedback --
        # confirmed by hardware: had to Ctrl+C out of a hang inside pyserial's
        # flush() on literally the first echo() call right after a successful
        # handshake, something that had worked fine on every earlier run. By the
        # time this is called, write() has already synchronously waited on
        # GetOverlappedResult() to confirm the bytes were physically handed to the
        # driver, so this is just extra insurance the UART finished shifting them
        # out -- bound it instead of trusting it blindly.
        #
        # max_wait was originally 2.0s -- correct in isolation, but usbwrite() calls
        # this after *every* chunk during bulk transfers (DA1 upload alone is ~1KB
        # chunks, i.e. potentially hundreds of calls). Confirmed on hardware: out_waiting
        # never clears quickly on this driver here either (same unreliability as
        # in_waiting), so every single chunk maxed out the full wait -- turning a bulk
        # upload into many minutes of dead time with zero progress output, indistinguishable
        # from a true hang (user had to Ctrl+C). Since write() already synchronously
        # confirmed the OS has the bytes before this even runs, this wait was never load
        # bearing for correctness -- shrink it to a token check instead of a real wait.
        try:
            deadline = time.time() + max_wait
            while self.device.out_waiting and time.time() < deadline:
                time.sleep(0.02)
        except Exception as e:
            self.debug(f"flush: out_waiting check failed ({e}), skipping")

    def flush(self):
        if self.get_device() is not None:
            self.device.flushOutput()
        self._bounded_flush()
        return None

    def usbread(self, resplen=None, maxtimeout=0, timeout=0, w_max_packet_size=None):
        # print("Reading {} bytes".format(resplen))
        if timeout == 0 and maxtimeout != 0:
            timeout = maxtimeout / 1000  # Some code calls this with ms delays, some with seconds.
        if timeout < 0.02:
            timeout = 0.02
        if resplen is None:
            # Sole remaining caller: DAXML.xread() (xml_lib.py), which asks for
            # exactly 1 byte here -- just enough to wait out the ~0.3s the DA needs to
            # start responding right after jump_da() (measured on hardware). It reads
            # the rest of each frame with explicit lengths once bytes are actively
            # flowing. This branch must NOT try to guess/drain extra bytes: an earlier
            # attempt hardcoded draining up to 16 bytes total (assuming every frame is
            # the same size), which corrupted framing whenever the true frame was only
            # 12 bytes and something else (next frame's data) followed right behind it
            # -- manifested as "xread: Wrong magic" a few frames in. Also: never
            # reassign self.device.timeout here (bug #4 / WinError 31 -- confirmed by
            # hardware test that even a value-changing reassignment right after the
            # DA1 upload burst crashes the VCOM driver on Windows).
            #
            # The wait_deadline below is a best-effort outer bound, not a hard one:
            # each self.device.read(1) call underneath still blocks for the *ambient*
            # self.device.timeout, which this branch deliberately never touches. What
            # actually keeps a single call from blocking far past 2s is the
            # constructor-level timeout=2 set once in connect() (a one-time value at
            # open, not a runtime reassignment -- see connect()'s comment) -- every
            # other read path in this file explicitly overrides device.timeout before
            # reading, so that default only governs this branch.
            start_wait = time.time()
            wait_deadline = start_wait + max(timeout, 2.0)
            first = b""
            while time.time() < wait_deadline:
                first = self.device.read(1)
                if len(first) > 0:
                    break
            if len(first) == 0:
                self.info(f"usbread: DA gave no data within {time.time() - start_wait:.2f}s of jump/request "
                          f"(resplen=None) -- device likely didn't start responding at all")
            return first
        # if resplen <= 0:
        #    self.info("Warning !")
        res = bytearray()
        loglevel = self.loglevel
        if self.device is None:
            return b""
        # Cuma panggil SetCommState (lewat property timeout) kalau nilainya berubah.
        # Reconfigure port yang tidak perlu, persis setelah burst write besar, rawan
        # kena ERROR_GEN_FAILURE (WinError 31) di driver VCOM MediaTek pada Windows.
        if self.device.timeout != timeout:
            self.device.timeout = timeout
        epr = self.device.read
        q = self.queue
        extend = res.extend
        bytestoread = resplen
        while bytestoread:
            bytestoread = resplen - len(res) if len(res) < resplen else 0
            if not q.empty():
                data = q.get(bytestoread)
                extend(data)
            if bytestoread <= 0:
                break
            try:
                val = epr(bytestoread)
                if len(val) == 0:
                    break
                if len(val) > bytestoread:
                    self.warning("Buffer overflow")
                    q.put(val[bytestoread:])
                    extend(val[:bytestoread])
                else:
                    extend(val)
            except Exception as e:
                error = str(e)
                if "timed out" in error:
                    if timeout is None:
                        return b""
                    self.debug("Timed out")
                    if timeout == 10:
                        return b""
                    timeout += 1
                    pass
                elif "Overflow" in error:
                    self.error("USB Overflow")
                    return b""
                else:
                    self.info(repr(e))
                    return b""

        if loglevel == logging.DEBUG:
            self.debug("SERIAL " + inspect.currentframe().f_back.f_code.co_name + ": length(" + hex(resplen) + ")")
            if self.loglevel == logging.DEBUG:
                self.verify_data(res[:resplen], "RX:")
        return res[:resplen]

    def usbxmlread(self, timeout=0):
        resplen = self.device.in_waiting
        res = bytearray()
        loglevel = self.loglevel
        self.device.timeout = timeout
        epr = self.device.read
        extend = res.extend
        bytestoread = max_xml_data_length
        while len(res) < bytestoread:
            try:
                val = epr(bytestoread)
                if len(val) == 0:
                    break
                extend(val)
                if res[-1] == b"\x00":
                    break
            except Exception as e:
                error = str(e)
                if "timed out" in error:
                    if timeout is None:
                        return b""
                    self.debug("Timed out")
                    if timeout == 10:
                        return b""
                    timeout += 1
                    pass
                elif "Overflow" in error:
                    self.error("USB Overflow")
                    return b""
                else:
                    self.info(repr(e))
                    return b""

        if loglevel == logging.DEBUG:
            self.debug("SERIAL " + inspect.currentframe().f_back.f_code.co_name + ": length(" + hex(resplen) + ")")
            if self.loglevel == logging.DEBUG:
                self.verify_data(res[:resplen], "RX:")
        return res[:resplen]

    def usbwrite(self, data, pktsize=None):
        if pktsize is None:
            # Chunk at the write packet size instead of len(data): a single
            # unchunked device.write() of a large buffer is what write_timeout=5
            # (see connect()) is sized against -- keep chunks <=get_write_packetsize()
            # so each device.write() call finishes well within that margin.
            pktsize = self.get_write_packetsize()
        res = self.write(data, pktsize)
        self._bounded_flush()
        return res

    def usbreadwrite(self, data, resplen):
        self.usbwrite(data)  # size
        self._bounded_flush()
        res = self.usbread(resplen)
        return res
