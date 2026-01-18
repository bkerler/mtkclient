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
    mtk = da_handler.configure_da(mtk, directory)
    return mtk, da_handler


def main():
    mtk=init(preloader=None, loader=None)
    mtk, da_handler = connect(mtk=mtk, directory=".")
    data=da_handler.da_rs(start=0,sectors=0x4000,filename="",parttype="user",display=False)
    print(data.hex())


if __name__ == '__main__':
    main()