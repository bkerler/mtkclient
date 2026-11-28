#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool (FlashtoollibEx / FlashToolLib.v1)
# Licensed under GPLv3 License
#
# MTK scatter file support for mtkclient.
# Ported from SP Flash Tool:
#  - text scatter (yaml_reader.cpp, ScatterFileParser@FlashToolLib.v1, DL_LoadScatter/DL_GetScatterInfo)
#  - xml scatter (SPFlashTool::XMLScatterFileGeneralSettingParserDecorator{V4,V5,V7,V8,V10,V11}
#    + XMLScatterFileStorageGeneralSettingParserBase)
#  - scatter_checksum.xml (flash.dll: images_sha256 / file[@name][@checksum])
from mtkclient.Library.Scatter.scatter import (ScatterPartition, ScatterInfo, ScatterError,
                                               ScatterChipMismatch, parse_scatter, parse_scatter_text,
                                               parse_scatter_xml, parse_scatter_checksum)

__all__ = ["ScatterPartition", "ScatterInfo", "ScatterError", "ScatterChipMismatch",
           "parse_scatter", "parse_scatter_text", "parse_scatter_xml", "parse_scatter_checksum"]
