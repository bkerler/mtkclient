from binascii import hexlify
from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.config.mtk_config import MtkConfig
from struct import pack


class Legacy_SdcInfo:
    m_sdmmc_info = None
    m_sdmmc_ua_size = None
    m_sdmmc_cid = None

    def __init__(self, config: MtkConfig = None, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.config = config
        self.m_sdmmc_info = sh.dword(direction='big')
        self.m_sdmmc_ua_size = sh.qword(direction='big')
        self.m_sdmmc_cid = sh.qwords(2, direction='big')

    def __repr__(self):
        print(f"m_sdmmc_info = {hex(self.m_sdmmc_info)}")
        print(f"m_sdmmc_ua_size = {hex(self.m_sdmmc_ua_size)}")
        cid = pack("<QQ", self.m_sdmmc_cid[0], self.m_sdmmc_cid[1])
        if self.config.hwparam is not None:
            self.config.set_cid(cid)
        print(f"m_sdmmc_cid = {hexlify(cid).decode('utf-8')}")


class Legacy_ConfigInfo:
    m_int_sram_ret = None
    m_int_sram_size = None
    m_ext_ram_ret = None
    m_ext_ram_type = None
    m_ext_ram_chip_select = None
    m_ext_ram_size = None
    randomid = None

    def __init__(self, data):
        sh = structhelper_io(data)
        self.m_int_sram_ret = sh.dword(direction='big')
        self.m_int_sram_size = sh.dword(direction='big')
        self.m_ext_ram_ret = sh.dword(direction='big')
        self.m_ext_ram_type = sh.bytes()
        self.m_ext_ram_chip_select = sh.bytes()
        self.m_ext_ram_size = sh.qword(direction='big')
        self.randomid = sh.qwords(2, direction='big')

    def __repr__(self):
        res = "m_int_sram_ret = 0x%X\n" % self.m_int_sram_ret
        res += "m_int_sram_size = 0x%X\n" % self.m_int_sram_size
        res += "m_ext_ram_ret = 0x%X\n" % self.m_ext_ram_ret
        res += "m_ext_ram_type = 0x%X\n" % self.m_ext_ram_type
        res += "m_ext_ram_chip_select = 0x%X\n" % self.m_ext_ram_chip_select
        res += "m_int_sram_ret = 0x%X\n" % self.m_int_sram_ret
        res += f"m_ext_ram_size = {hex(self.m_ext_ram_size)}\n"
        res += "randomid = 0x%X%X\n" % (self.randomid[0], self.randomid[1])
        return res


class Legacy_NandInfo64:
    m_nand_info = None
    m_nand_chip_select = None
    m_nand_flash_id = None
    m_nand_flash_size = None
    m_nand_flash_id_count = None
    info2 = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nand_info = sh.dword(direction='big')
        self.m_nand_chip_select = sh.bytes()
        self.m_nand_flash_id = sh.short(direction='big')
        self.m_nand_flash_size = sh.qword(direction='big')
        self.m_nand_flash_id_count = sh.short(direction='big')
        self.info2 = None

    def __repr__(self):
        res = f"m_nand_info = {hex(self.m_nand_info)}\n"
        res += f"m_nand_chip_select = {hex(self.m_nand_chip_select)}\n"
        res += f"m_nand_flash_id = {hex(self.m_nand_flash_id)}\n"
        res += f"m_nand_flash_size = {hex(self.m_nand_flash_size)}\n"
        res += f"m_nand_flash_id_count = {hex(self.m_nand_flash_id_count)}\n"
        return res


# ('m_nand_flash_dev_code', '>7H'),

class Legacy_NandInfo2:
    m_nand_pagesize = None
    m_nand_sparesize = None
    m_nand_pages_per_block = None
    m_nand_io_interface = None
    m_nand_addr_cycle = None
    m_nand_bmt_exist = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nand_pagesize = sh.short(direction='big')
        self.m_nand_sparesize = sh.short(direction='big')
        self.m_nand_pages_per_block = sh.short(direction='big')
        self.m_nand_io_interface = sh.bytes()
        self.m_nand_addr_cycle = sh.bytes()
        self.m_nand_bmt_exist = sh.bytes()

    def __repr__(self):
        res = f"m_nand_pagesize = {hex(self.m_nand_pagesize)}\n"
        res += f"m_nand_sparesize = {hex(self.m_nand_sparesize)}\n"
        res += f"m_nand_pages_per_block = {hex(self.m_nand_pages_per_block)}\n"
        res += f"m_nand_io_interface = {hex(self.m_nand_io_interface)}\n"
        res += f"m_nand_addr_cycle = {hex(self.m_nand_addr_cycle)}\n"
        res += f"m_nand_bmt_exist = {hex(self.m_nand_bmt_exist)}\n"
        return res


class Legacy_EmmcInfo:
    m_emmc_ret = None
    m_emmc_boot1_size = None
    m_emmc_boot2_size = None
    m_emmc_rpmb_size = None
    m_emmc_gp_size = None
    m_emmc_ua_size = None
    m_emmc_cid = None
    m_emmc_fwver = None

    def __init__(self, config: MtkConfig = None, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.config = config
        self.m_emmc_ret = sh.dword(direction='big')
        self.m_emmc_boot1_size = sh.qword(direction='big')
        self.m_emmc_boot2_size = sh.qword(direction='big')
        self.m_emmc_rpmb_size = sh.qword(direction='big')
        self.m_emmc_gp_size = sh.qwords(4, direction='big')
        self.m_emmc_ua_size = sh.qword(direction='big')
        self.m_emmc_cid = sh.qwords(2, direction='big')
        self.m_emmc_fwver = sh.bytes(8)

    def __repr__(self):
        res = f"m_emmc_ret = {hex(self.m_emmc_ret)}\n"
        res += f"m_emmc_boot1_size = {hex(self.m_emmc_boot1_size)}\n"
        res += f"m_emmc_boot2_size = {hex(self.m_emmc_boot2_size)}\n"
        res += f"m_emmc_rpmb_size = {hex(self.m_emmc_rpmb_size)}\n"
        res += f"m_emmc_gp_size[0] = {hex(self.m_emmc_gp_size[0])}\n"
        res += f"m_emmc_gp_size[1] = {hex(self.m_emmc_gp_size[1])}\n"
        res += f"m_emmc_gp_size[2] = {hex(self.m_emmc_gp_size[2])}\n"
        res += f"m_emmc_gp_size[3] = {hex(self.m_emmc_gp_size[3])}\n"
        res += f"m_emmc_ua_size = {hex(self.m_emmc_ua_size)}\n"
        cid = pack("<QQ", self.m_emmc_cid[0], self.m_emmc_cid[1])
        res += f"m_emmc_cid = {hexlify(cid).decode('utf-8')}\n"
        if self.config.hwparam is not None:
            self.config.set_cid(cid)
        res += f"m_emmc_fwver = {hexlify(self.m_emmc_fwver).decode('utf-8')}\n"
        return res


class Legacy_NandInfo32:
    m_nand_info = None
    m_nand_chip_select = None
    m_nand_flash_id = None
    m_nand_flash_size = None
    m_nand_flash_id_count = None
    info2 = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nand_info = sh.dword(direction='big')
        self.m_nand_chip_select = sh.bytes()
        self.m_nand_flash_id = sh.short(direction='big')
        self.m_nand_flash_size = sh.dword(direction='big')
        self.m_nand_flash_id_count = sh.short(direction='big')
        self.info2 = None

    def __repr__(self):
        res = f"m_nand_info = {hex(self.m_nand_info)}\n"
        res += f"m_nand_chip_select = {hex(self.m_nand_chip_select)}\n"
        res += f"m_nand_flash_id = {hex(self.m_nand_flash_id)}\n"
        res += f"m_nand_flash_size = {hex(self.m_nand_flash_size)}\n"
        res += f"m_nand_flash_id_count = {hex(self.m_nand_flash_id_count)}\n"
        return res


class Legacy_NorInfo:
    m_nor_ret = None
    m_nor_chip_select = None
    m_nor_flash_id = None
    m_nor_flash_size = None
    m_nor_flash_dev_code = None
    m_nor_flash_otp_status = None
    m_nor_flash_otp_size = None
    m_sdmmc_ua_size = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nor_ret = sh.dword(direction='big')
        self.m_nor_chip_select = sh.bytes(2)
        self.m_nor_flash_id = sh.short(direction='big')
        self.m_nor_flash_size = sh.dword(direction='big')
        self.m_nor_flash_dev_code = sh.shorts(4, direction='big')
        self.m_nor_flash_otp_status = sh.dword(direction='big')
        self.m_nor_flash_otp_size = sh.dword(direction='big')

    def __repr__(self):
        res = f"m_nor_ret = {hex(self.m_nor_ret)}\n"
        res += f"m_nor_chip_select = {hexlify(self.m_nor_chip_select).decode('utf-8')}\n"
        res += f"m_nor_flash_id = {hex(self.m_nor_flash_id)}\n"
        res += f"m_nor_flash_size = {hex(self.m_nor_flash_size)}\n"
        val = pack("<HHHH", self.m_nor_flash_dev_code[0], self.m_nor_flash_dev_code[1], self.m_nor_flash_dev_code[2],
                   self.m_nor_flash_dev_code[3])
        res += f"m_nor_flash_dev_code = {hexlify(val).decode('utf-8')}\n"
        res += f"m_nor_flash_otp_status = {hex(self.m_nor_flash_otp_status)}\n"
        res += f"m_nor_flash_otp_size = {hex(self.m_nor_flash_otp_size)}\n"

        res += f"m_sdmmc_cid = {hexlify(val).decode('utf-8')}\n"
        return res
