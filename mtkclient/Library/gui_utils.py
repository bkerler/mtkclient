#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023
# GPLv3 License

import copy
import logging
import math
import os
import sys
from io import BytesIO
import time
from datetime import datetime
import colorama
import logging.config


class progress:
    def __init__(self, total: int, pagesize: int = 1, prefix: str = '', display: bool = True, guiprogress=None, offset: int = 0):
        self.progtime = 0
        self.pos = offset
        self.prog = 0
        self.display = display
        self.start = None
        self.progtime = None
        self.total = total + offset
        self.prefix = prefix
        self.pagesize = pagesize
        self.oldpos = offset
        self.oldtime = time.time()
        self.offset = offset
        if guiprogress is not None:
            self.guiprogress = guiprogress.emit
        else:
            self.guiprogress = None

    def clear(self):
        self.start = time.time()
        self.progtime = time.time()
        self.pos = self.offset
        self.prog = 0

    def calcProcessTime(self, starttime, cur_iter, max_iter):
        telapsed = time.time() - starttime
        if telapsed > 0 and cur_iter > 0:
            testimated = (telapsed / cur_iter) * max_iter
            finishtime = starttime + testimated
            finishtime = datetime.fromtimestamp(finishtime).strftime("%H:%M:%S")  # in time
            lefttime = testimated - telapsed  # in seconds
            return int(telapsed), int(lefttime), finishtime
        else:
            return 0, 0, ""

    def done(self):
        if self.pos != self.total:
            self.print_progress(100, 100, prefix='Progress:',
                                suffix=self.prefix + ' (0x%X/0x%X),%0.2f MB/s' % (self.total // self.pagesize,
                                                                                  self.total // self.pagesize,
                                                                                  0), bar_length=10)

    def convert_size(self, size_bytes):
        if size_bytes <= 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return "%s %s" % (s, size_name[i])

    def print_progress(self, iteration, total, prefix='', suffix='', decimals=1, bar_length=10):
        """
        Call in a loop to create terminal progress bar
        @params:
            iteration   - Required  : current iteration (Int)
            total       - Required  : total iterations (Int)
            prefix      - Optional  : prefix string (Str)
            suffix      - Optional  : suffix string (Str)
            decimals    - Optional  : positive number of decimals in percent complete (Int)
            bar_length  - Optional  : character length of bar (Int)
        """
        str_format = "{0:." + str(decimals) + "f}"
        percents = str_format.format(100 * (iteration / float(total)))
        filled_length = int(round(bar_length * iteration / float(total)))
        bar = '█' * filled_length + '-' * (bar_length - filled_length)

        sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix))

        if iteration == total:
            sys.stdout.write('\n')
        sys.stdout.flush()

    def update(self, length: int):
        self.pos += length
        if self.pos != 0:
            prog = float(self.pos) / float(self.total) * 100.0
        else:
            prog = 0.0
        if self.guiprogress is not None:
            self.guiprogress(self.pos)
        else:
            if not self.start:
                curtime = time.time()
                self.start = curtime
                self.progtime = curtime
                self.prog = prog
                self.oldpos = 0
                self.print_progress(prog, 100, prefix='Done',
                                    suffix=self.prefix + ' (0x%X/0x%X),%0.2f MB/s' % (self.pos // self.pagesize,
                                                                                      self.total // self.pagesize,
                                                                                      0), bar_length=10)
            if prog > self.prog:
                if self.display:
                    t0 = time.time()
                    self.progtime = t0
                    throughput = self.pos - self.oldpos
                    self.oldpos = self.pos
                    difftime = self.progtime - self.oldtime
                    if difftime > 0:
                        throughput /= difftime
                    self.oldtime = self.progtime
                    telapsed, lefttime, finishtime = self.calcProcessTime(self.start, prog, 100)
                    hinfo = ""
                    if lefttime > 0:
                        sec = lefttime
                        if sec > 60:
                            min = sec // 60
                            sec = sec % 60
                            if min > 60:
                                h = min // 24
                                min = min % 24
                                hinfo = "%02dh:%02dm:%02ds left" % (h, min, sec)
                            else:
                                hinfo = "%02dm:%02ds left" % (min, sec)
                        else:
                            hinfo = "%02ds left" % sec

                    self.print_progress(prog, 100, prefix='Progress:',
                                        suffix=self.prefix + f' (0x%X/0x%X), %s/s {hinfo} ' % (
                                            self.pos // self.pagesize,
                                            self.total // self.pagesize,
                                            self.convert_size(throughput)), bar_length=10)
                    self.prog = prog

class ColorFormatter(logging.Formatter):
    LOG_COLORS = {
        logging.ERROR: colorama.Fore.RED,
        logging.DEBUG: colorama.Fore.LIGHTMAGENTA_EX,
        logging.WARNING: colorama.Fore.YELLOW,
    }

    def format(self, record, *args, **kwargs):
        # if the corresponding logger has children, they may receive modified
        # record, so we want to keep it intact
        new_record = copy.copy(record)
        if new_record.levelno in self.LOG_COLORS:
            pad = ""
            if new_record.name != "root":
                print(new_record.name)
                pad = "[LIB]: "
            # we want levelname to be in different color, so let"s modify it
            new_record.msg = "{pad}{color_begin}{msg}{color_end}".format(
                pad=pad,
                msg=new_record.msg,
                color_begin=self.LOG_COLORS[new_record.levelno],
                color_end=colorama.Style.RESET_ALL,
            )
        # now we can let standart formatting take care of the rest
        return super(ColorFormatter, self).format(new_record, *args, **kwargs)


class LogBase(type):
    debuglevel = logging.root.level

    def __init__(cls, *args):
        super().__init__(*args)
        logger_attribute_name = "_" + cls.__name__ + "__logger"
        logger_debuglevel_name = "_" + cls.__name__ + "__debuglevel"
        logger_name = ".".join([c.__name__ for c in cls.mro()[-2::-1]])
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "root": {
                    "()": ColorFormatter,
                    "format": "%(name)s - %(message)s",
                }
            },
            "handlers": {
                "root": {
                    # "level": cls.__logger.level,
                    "formatter": "root",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                "": {
                    "handlers": ["root"],
                    # "level": cls.debuglevel,
                    "propagate": False
                }
            },
        }
        logging.config.dictConfig(log_config)
        logger = logging.getLogger(logger_name)

        setattr(cls, logger_attribute_name, logger)
        setattr(cls, logger_debuglevel_name, cls.debuglevel)
        cls.logsetup = logsetup


def logsetup(self, logger, loglevel, signal=None):
    if not signal:
        self.info = logger.info
        self.debug = logger.debug
        self.error = logger.error
        self.warning = logger.warning
    else:
        self.info = signal.emit
        self.debug = signal.emit
        self.error = signal.emit
        self.warning = signal.emit
    if loglevel == logging.DEBUG:
        logfilename = os.path.join("logs", "log.txt")
        if not os.path.exists(os.path.dirname(logfilename)):
            os.makedirs(os.path.dirname(logfilename))
        fh = logging.FileHandler(logfilename, encoding='utf-8')
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    self.loglevel = loglevel
    return logger, self.info, self.debug, self.warning, self.error


class structhelper_io:
    pos = 0

    def __init__(self, data: (BytesIO, bytearray, bytes) = None, direction='little'):
        self.direction = direction
        self.pos = 0
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = BytesIO(bytearray(data))
        self.data = data

    def setdata(self, data, offset=0):
        self.pos = offset
        self.data = data

    def qwords(self, qwords=1, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(8), direction) for _ in range(qwords)]
        self.pos += 8 * qwords
        return dat

    def qword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(8), direction)
        self.pos += 8
        return dat

    def dword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(4), direction)
        self.pos += 4
        return dat

    def dwords(self, dwords=1, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(4), direction) for _ in range(dwords)]
        self.pos += 4 * dwords
        return dat

    def short(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(2), direction)
        self.pos += 2
        return dat

    def shorts(self, shorts, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(2), direction) for _ in range(shorts)]
        self.pos += 2 * shorts
        return dat

    def bytes(self, rlen=1):
        dat = self.data.read(rlen)
        self.pos += rlen
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def string(self, rlen=1):
        dat = b""
        while len(dat) < rlen:
            tmp = self.data.read(1)
            self.pos += 1
            if tmp == b"\x00":
                break
            dat += tmp
        try:
            dat = dat.decode('utf-8')
        except Exception:
            dat = dat
        return dat

    def ustring(self, rlen=1):
        dat = b""
        while len(dat) < rlen:
            tmp = self.data.read(2)
            self.pos += 2
            if tmp == b"\x00\x00":
                break
            dat += tmp
        try:
            dat = dat.decode('utf-16')
        except Exception:
            dat = dat
        return dat

    def getpos(self):
        return self.pos

    def seek(self, pos):
        self.data.seek(pos)
        self.pos = pos

    def read(self, rlen=1):
        self.pos += rlen
        return self.data.read(rlen)
