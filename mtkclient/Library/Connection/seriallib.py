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

        ports = self.detectdevices()
        if ports:
            if self.portname != "DETECT":
                if self.portname not in ports:
                    self.info("{} not in detected ports: {}".format(self.portname, ports))
                    return False
                else:
                    port = ports[ports.index(self.portname)]
            else:
                port = ports[0]
            self.debug("Got port: {}, initializing".format(port))
            self.device = serial.Serial(port=port, baudrate=115200, bytesize=serial.EIGHTBITS,
                                        parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                                        timeout=500,
                                        xonxoff=False, dsrdtr=False, rtscts=False)
            self.portname = port
        else:
            return False
        self.device._reset_input_buffer = _reset_input_buffer
        try:
            self.device.open()
        except Exception as e:
            self.debug(e)
            pass
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
                    self.debug(str(err))
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

    def flush(self):
        if self.get_device() is not None:
            self.device.flushOutput()
        return self.device.flush()

    def usbread(self, resplen=None, maxtimeout=0, timeout=0, w_max_packet_size=None):
        # print("Reading {} bytes".format(resplen))
        if timeout == 0 and maxtimeout != 0:
            timeout = maxtimeout / 1000  # Some code calls this with ms delays, some with seconds.
        if timeout < 0.02:
            timeout = 0.02
        if resplen is None:
            resplen = self.device.in_waiting
        # if resplen <= 0:
        #    self.info("Warning !")
        res = bytearray()
        loglevel = self.loglevel
        if self.device is None:
            return b""
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
            pktsize = len(data)
        res = self.write(data, pktsize)
        self.device.flush()
        return res

    def usbreadwrite(self, data, resplen):
        self.usbwrite(data)  # size
        self.device.flush()
        res = self.usbread(resplen)
        return res
