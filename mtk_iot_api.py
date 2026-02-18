#!/usr/bin/env python3
import logging
import os
import sys

from mtkclient.Library.DA.mtk_da_handler import DaHandler
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.mtk_class import Mtk
from mtkclient.config.mtk_config import MtkConfig


def init(preloader, loader, serialport=None):
    loglevel = logging.INFO
    config = MtkConfig(loglevel=loglevel, gui=None, guiprogress=None)
    config.loader = loader
    if preloader is not None:
        if os.path.exists(preloader):
            config.preloader_filename = preloader
            config.preloader = open(config.preloader_filename, "rb").read()
    mtk = Mtk(config=config, loglevel=loglevel, serialportname=serialport)
    return mtk

def connect(mtk, directory=".", loglevel=logging.INFO):
    da_handler = DaHandler(mtk, loglevel)
    mtk = da_handler.connect(mtk, directory)
    if mtk is None:
        return None, None
    mtk = da_handler.configure_da(mtk)
    return mtk, da_handler


def main():
    bytestoread=0x400000
    pos=0
    mtk = init(preloader=None, loader=None,serialport="/dev/ttyUSB0")
    mtk.config.iot = True
    with open("dump.bin","wb") as wf:
        while bytestoread>0:
            inited = mtk.preloader.init(directory="")
            if inited:
                data=mtk.preloader.dump_internal_flash(offset=pos,length=bytestoread,step=0x1000,filename="")
                if len(data)>0:
                    pos+=len(data)
                    bytestoread-=len(data)
                    wf.write(data)

if __name__ == '__main__':
    main()