from binascii import hexlify
from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.config.mtk_config import MtkConfig
from struct import pack


class ConfigInfoIoT:
    m_int_sram_ret = None
    m_int_sram_size = None
    m_ext_ram_ret = None
    m_ext_ram_type = None
    m_ext_ram_chip_select = None
    m_ext_ram_size = None

    def __init__(self, data):
        sh = structhelper_io(data)
        self.m_int_sram_ret = sh.dword(direction='big')
        self.m_int_sram_size = sh.dword(direction='big')
        self.m_ext_ram_ret = sh.dword(direction='big')
        self.m_ext_ram_type = sh.bytes()
        self.m_ext_ram_chip_select = sh.bytes()
        self.m_ext_ram_size = sh.dword(direction='big')
        self.sf_candidate = sh.bytes(12)

    def __repr__(self):
        res = "m_int_sram_ret = 0x%X\n" % self.m_int_sram_ret
        res += "m_int_sram_size = 0x%X\n" % self.m_int_sram_size
        res += "m_ext_ram_ret = 0x%X\n" % self.m_ext_ram_ret
        res += "m_ext_ram_type = 0x%X\n" % self.m_ext_ram_type
        res += "m_ext_ram_chip_select = 0x%X\n" % self.m_ext_ram_chip_select
        res += "m_int_sram_ret = 0x%X\n" % self.m_int_sram_ret
        res += f"m_ext_ram_size = {hex(self.m_ext_ram_size)}\n"
        res += f"sf_candidate = {self.sf_candidate.hex()}\n"
        return res


class EmmcInfoIoT:
    m_emmc_ret = None
    m_emmc_boot1_size = None
    m_emmc_boot2_size = None
    m_emmc_rpmb_size = None
    m_emmc_gp_size = None
    m_emmc_ua_size = None
    m_emmc_cid = None
    m_emmc_fwver = None

    def __init__(self, config: MtkConfig, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.config = config
        self.m_emmc_ret = sh.dword(direction='big')
        self.m_emmc_manufacturer_id = sh.bytes()
        self.m_emmc_product_name = sh.bytes(6)
        self.m_emmc_partitioned = sh.bytes()
        self.m_emmc_boot1_size = sh.dword(direction='big')
        self.m_emmc_boot2_size = sh.dword(direction='big')
        self.m_emmc_rpmb_size = sh.dword(direction='big')
        self.m_emmc_gp_size = sh.dwords(4, direction='big')
        self.m_emmc_ua_size = sh.dword(direction='big')

    def __repr__(self):
        res = f"m_emmc_ret = {hex(self.m_emmc_ret)}\n"
        res += f"m_emmc_manufacturer_id = {hex(self.m_emmc_manufacturer_id)}\n"
        res += f"m_emmc_product_name = {self.m_emmc_product_name.hex()}\n"
        res += f"m_emmc_partitioned = {hex(self.m_emmc_partitioned)}\n"
        res += f"m_emmc_boot1_size = {hex(self.m_emmc_boot1_size)}\n"
        res += f"m_emmc_boot2_size = {hex(self.m_emmc_boot2_size)}\n"
        res += f"m_emmc_rpmb_size = {hex(self.m_emmc_rpmb_size)}\n"
        res += f"m_emmc_gp_size[0] = {hex(self.m_emmc_gp_size[0])}\n"
        res += f"m_emmc_gp_size[1] = {hex(self.m_emmc_gp_size[1])}\n"
        res += f"m_emmc_gp_size[2] = {hex(self.m_emmc_gp_size[2])}\n"
        res += f"m_emmc_gp_size[3] = {hex(self.m_emmc_gp_size[3])}\n"
        res += f"m_emmc_ua_size = {hex(self.m_emmc_ua_size)}\n"
        return res


class NandInfoIoT:
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
        self.m_nand_flash_dev_code = sh.shorts(4, direction='big')
        self.m_nand_flash_dev_code_part2 = sh.shorts(4, direction='big')
        self.m_nand_pagesize = sh.short()
        self.m_nand_sparesize = sh.short()
        self.m_nand_pages_per_block = sh.short()
        self.m_nand_io_interface = sh.bytes()
        self.m_nand_addr_cycle = sh.bytes()
        self.info2 = None

    def __repr__(self):
        res = f"m_nand_info = {hex(self.m_nand_info)}\n"
        res += f"m_nand_chip_select = {hex(self.m_nand_chip_select)}\n"
        res += f"m_nand_flash_id = {hex(self.m_nand_flash_id)}\n"
        res += f"m_nand_flash_size = {hex(self.m_nand_flash_size)}\n"
        val = pack("<HHHH", self.m_nand_flash_dev_code[0], self.m_nand_flash_dev_code[1], self.m_nand_flash_dev_code[2],
                   self.m_nand_flash_dev_code[3])
        res += f"m_nand_flash_dev_code = {hexlify(val).decode('utf-8')}\n"
        val = pack("<HHHH", self.m_nand_flash_dev_code_part2[0], self.m_nand_flash_dev_code_part2[1],
                   self.m_nand_flash_dev_code_part2[2],
                   self.m_nand_flash_dev_code_part2[3])
        res += f"m_nand_flash_dev_code_part2 = {hexlify(val).decode('utf-8')}\n"
        res += f"m_nand_pagesize = {hex(self.m_nand_pagesize)}\n"
        res += f"m_nand_sparesize = {hex(self.m_nand_sparesize)}\n"
        res += f"m_nand_pages_per_block = {hex(self.m_nand_pages_per_block)}\n"
        res += f"m_nand_io_interface = {hex(self.m_nand_io_interface)}\n"
        res += f"m_nand_addr_cycle = {hex(self.m_nand_addr_cycle)}\n"
        return res


class NorInfoIoT2523:
    m_nor_ret = None
    m_nor_chip_select = None
    m_nor_flash_id = None
    m_nor_flash_size = None
    m_nor_flash_dev_code = None
    m_nor_flash_otp_status = None
    m_nor_flash_otp_size = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nor_base_addr = sh.dword(direction='big')
        self.m_nor_flash_size = sh.dword(direction='big')

        class dieinfo:
            def __init__(self, sh):
                self.m_nor_flash_otp_status = 0
                self.m_nor_flash_otp_size = 0
                self.m_nor_flash_name = sh.short(direction='big')
                self.m_nor_flash_size = sh.dword(direction='big')
                self.m_nor_flash_dev_codes = sh.shorts(3, direction='big')

        self.die = []
        for i in range(2):
            self.die.append(dieinfo(sh))
        self.die[0].m_nor_flash_otp_status = sh.dword(direction='big')
        self.die[0].m_nor_flash_otp_size = sh.dword(direction='big')
        self.die[1].m_nor_flash_otp_status = sh.dword(direction='big')
        self.die[1].m_nor_flash_otp_size = sh.dword(direction='big')

        self.m_int_sram_ret = sh.bytes(1)
        self.m_int_sram_size = sh.dword()
        self.m_ext_sram_ret = sh.bytes(1)
        self.m_ext_sram_size = sh.dword()

    def __repr__(self):
        return f"NOR Physical offset: {hex(self.m_nor_base_addr)}\nNOR Physical size: {hex(self.m_nor_flash_size)}\n"


class NorInfoIoT:
    m_nor_ret = None
    m_nor_chip_select = None
    m_nor_flash_id = None
    m_nor_flash_size = None
    m_nor_flash_dev_code = None
    m_nor_flash_otp_status = None
    m_nor_flash_otp_size = None

    def __init__(self, data=None):
        if data is None:
            return
        sh = structhelper_io(data)
        self.m_nor_ret = sh.dword(direction='big')
        self.m_nor_chip_select = sh.bytes(2)
        self.m_nor_flash_id = sh.short(direction='big')
        self.m_nor_flash_size = sh.dword(direction='big')
        self.m_nor_flash_size_die1 = sh.dword(direction='big')
        self.m_nor_flash_dev_code = sh.shorts(4, direction='big')
        self.m_nor_flash_otp_status = sh.dword(direction='big')
        self.m_nor_flash_otp_size = sh.dword(direction='big')

        self.m_nor_flash_id_die2 = sh.short(direction='big')
        self.m_nor_flash_size_die2 = sh.dword(direction='big')
        self.m_nor_flash_dev_code_die2 = sh.shorts(4, direction='big')
        self.m_nor_flash_otp_status_die2 = sh.dword(direction='big')
        self.m_nor_flash_otp_size_die2 = sh.dword(direction='big')

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
        res += f"m_nor_flash_id_die2 = {hex(self.m_nor_flash_id)}\n"
        res += f"m_nor_flash_size_die2 = {hex(self.m_nor_flash_size)}\n"
        val = pack("<HHHH", self.m_nor_flash_dev_code[0], self.m_nor_flash_dev_code[1], self.m_nor_flash_dev_code[2],
                   self.m_nor_flash_dev_code[3])
        res += f"m_nor_flash_dev_code_die2 = {hexlify(val).decode('utf-8')}\n"
        res += f"m_nor_flash_otp_status_die2 = {hex(self.m_nor_flash_otp_status)}\n"
        res += f"m_nor_flash_otp_size_die2 = {hex(self.m_nor_flash_otp_size)}\n"
        return res
