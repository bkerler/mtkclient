import datetime
from mtkclient.Library.gui_utils import LogBase


class BootModes:
    fastboot = "FASTBOOT"
    meta = "META"
    testmode = "ANDROID-TEST-MODE"


class XMLCmd(metaclass=LogBase):

    def __init__(self, mtk):
        self.mtk = mtk
        self.MAGIC = 0xFEEEEEEF

    @staticmethod
    def create_cmd(cmd: str, content: dict = None, version="1.0"):
        cmd = f"<?xml version=\"1.0\" encoding=\"utf-8\"?><da><version>{version}</version><command>CMD:{cmd}</command>"
        if content is not None:
            for item in content:
                cmd += f"<{item}>"
                for subitem in content[item]:
                    cmd += f"{subitem}"
                cmd += f"</{item}>"
        cmd += "</da>"
        return cmd

    # DA1

    def cmd_notify_init_hw(self):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
        <version>1.0</version>
        <command>CMD:NOTIFY-INIT-HW</command>
        <arg></arg>
        </da>
        """
        cmd = self.create_cmd("NOTIFY-INIT-HW")
        return cmd

    def cmd_security_set_flash_policy(self, host_offset: int = 0x8000000,
                                      length: int = 0x100000):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
        <command>CMD:SECURITY-SET-FLASH-POLICY</command><arg>
        <source_file>MEM://0x8000000:0x100000</source_file></arg></da>
        """
        content = {
            "arg": [
                f"<source_file>MEM://{hex(host_offset)}:{hex(length)}</source_file>"
            ]
        }
        cmd = self.create_cmd("SECURITY-SET-FLASH-POLICY", content)
        return cmd

    def cmd_security_set_allinone_signature(self, host_offset: int = 0x8000000,
                                      length: int = 0x100000, filename:str=None):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
        <command>CMD:SECURITY-SET-ALLINONE-SIGNATURE</command><arg>
        <source_file>MEM://0x8000000:0x100000</source_file></arg></da>
        """
        if filename is None:
            filename = f"MEM://{hex(host_offset)}:{hex(length)}"
        content = {
            "arg": [
                f"<source_file>{filename}</source_file>",
            ]
        }
        cmd = self.create_cmd("SECURITY-SET-ALLINONE-SIGNATURE", content)
        return cmd


    def cmd_boot_to(self, at_addr: int = 0x40000000, jmp_addr: int = 0x40000000, host_offset: int = 0x7fe83c09a04c,
                    length: int = 0x50c78):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:BOOT-TO</command><arg>
        <at_address>0x40000000</at_address><jmp_address>0x40000000</jmp_address>
        <source_file>MEM://0x7fe83c09a04c:0x50c78</source_file></arg></da>
        """
        content = {
            "arg": [
                f"<at_address>{hex(at_addr)}</at_address>",
                f"<jmp_address>{hex(jmp_addr)}</jmp_address>",
                f"<source_file>MEM://{hex(host_offset)}:{hex(length)}</source_file>"
            ]
        }
        cmd = self.create_cmd("BOOT-TO", content)
        return cmd

    """
    def cmd_reboot(disconnect: bool = False):
    def cmd_get_hw_info(mem_offset=0x8000000, mem_length=0x100000):
    """

    def cmd_set_runtime_parameter(self, checksum_level: str = "NONE", battery_exist: str = "AUTO-DETECT",
                                  da_log_level: str = "INFO", log_channel: str = "UART", system_os: str = "LINUX",
                                  version: str = "1.1", initialize_dram: bool = True):
        cmd = f"""<?xml version="1.0" encoding="utf-8"?>
<da>
    <version>1.1</version>
    <command>CMD:SET-RUNTIME-PARAMETER</command>
    <arg>
        <checksum_level>{checksum_level}</checksum_level>
        <battery_exist>{battery_exist}</battery_exist>
        <da_log_level>{da_log_level}</da_log_level>
        <log_channel>{log_channel}</log_channel>
        <system_os>{system_os}</system_os>
    </arg>
    <adv>
        <initialize_dram>{"YES" if initialize_dram else "NO"}</initialize_dram>
    </adv>
</da>\x00"""
        if initialize_dram is not None:
            dram = "YES" if initialize_dram else "NO"
        else:
            dram = "YES"
        content = {
            "arg": [
                f"<checksum_level>{checksum_level}</checksum_level>",
                f"<battery_exist>{battery_exist}</battery_exist>",
                f"<da_log_level>{da_log_level}</da_log_level>",
                f"<log_channel>{log_channel}</log_channel>",
                f"<system_os>{system_os}</system_os>"],
            "adv": [
                f"<initialize_dram>{dram}</initialize_dram>"
            ]
        }
        # checksum_level (NONE,USB,STORAGE,USB-STORAGE)
        # da_log_level (TRACE,DEBUG,INFO,WARN,ERROR)
        # log_channel (USB/UART)
        # battery_exist (YES,NO,AUTO-DETECT)
        cmd = self.create_cmd("SET-RUNTIME-PARAMETER", content, version)
        return cmd

    def cmd_host_supported_commands(self,
                                    host_capability: str = "CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1" +
                                                           "@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@"):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:HOST-SUPPORTED-COMMANDS</command>
        <arg><host_capability>CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@
        </host_capability></arg></da>\x00
        """
        content = {
            "arg": [
                f"<host_capability>{host_capability}</host_capability>"
            ]
        }
        cmd = self.create_cmd("HOST-SUPPORTED-COMMANDS", content)
        return cmd

    def cmd_ram_test(self, function: str = "FLIP", start_address: int = 0x4000000, length: int = 0x100000,
                     repeat: int = 0xA):
        if function == "FLIP":
            content = {
                "arg": [
                    "<function>FLIP</function>",
                    f"<start_address>{hex(start_address)}</start_address>",
                    f"<length>{hex(length)}</length>",
                    f"<repeat>{hex(repeat)}</repeat>"
                ]
            }
        else:
            content = {
                "arg": [
                    "<function>CALIBRATION</function>",
                    "<target_file>ms-appdata:///local/calib.bin</target_file>"
                ]
            }
        cmd = self.create_cmd("RAM-TEST", content)
        # resp =
        """
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version><command>CMD:UPLOAD-FILE</command><arg>
        <checksum>CHK_NO</checksum><info>WriteLocalFile</info><target_file>%s</target_file>
        <packet_length>0x%x</packet_length></arg></host>
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version><command>CMD:PROGRESS-REPORT</command>
        <arg><message>RAM test.</message></arg></host>
        or
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version><command>CMD:PROGRESS-REPORT</command>
        <arg><message>Interface diag</message></arg></host>
        """
        return cmd

    def cmd_dram_repair(self, mem_offset: int = 0x10000, mem_length: int = 0x1000):
        content = {
            "arg": [
                "<param_file>D:/dram.info</param_file>",
                f"<target_file>MEM://{mem_offset}:{mem_length}</target_file>"
            ]
        }
        cmd = self.create_cmd("DRAM-REPAIR", content)
        # INFO Result: SUCCEEDED, NO-NEED, FAILED
        return cmd

    # DA2
    def cmd_read_partition_table(self, host_mem_offset: int = 0x7fe83c538720, length: int = 0x200000):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
            <version>1.0</version>
            <command>CMD:READ-PARTITION-TABLE</command>
            <arg>
                <target_file>MEM://0x7fe83c538720:0x200000</target_file>
            </arg>
        </da>
        """
        content = {
            "arg": [
                f"<target_file>MEM://{hex(host_mem_offset)}:{hex(length)}</target_file>"
            ]
        }

        cmd = self.create_cmd("READ-PARTITION-TABLE", content)
        # resp =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <partition_table version="1.0">
        <pt>
            <name>proinfo</name>
            <start>0x8000</start>
            <size>0x300000</size>
        </pt>
        <pt>
            <name>misc</name>
            <start>0x308000</start>
            <size>0x80000</size>
        </pt>
        <pt>
            <name>para</name>
            <start>0x388000</start>
            <size>0x80000</size>
        </pt>
        <pt>
            <name>expdb</name>
            <start>0x408000</start>
            <size>0x8000000</size>
        </pt>
        </partition_table>
        """
        return cmd

    def cmd_can_higher_usb_speed(self, host_mem_offset: int = 0x7fe8463ed240, length: int = 0x40):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
        <command>CMD:CAN-HIGHER-USB-SPEED</command><arg><target_file>MEM://0x7fe8463ed240:0x40</target_file></arg></da>
        """
        content = {
            "arg": [
                f"<target_file>MEM://{hex(host_mem_offset)}:{hex(length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("CAN-HIGHER-USB-SPEED", content)
        return cmd

    def cmd_write_efuse(self):
        content = {
            "arg": [
                "<source_file>ms-appdata:///local/efuse.xml</source_file>"
            ]
        }
        cmd = self.create_cmd("WRITE-EFUSE", content)
        # resp =
        """
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version>
        <command>CMD:DOWNLOAD-FILE</command><a"rg><checksum>%s</checksum>
        <info>%s</info><source_file>%s</source_file><packet_length>0x%x</packet_length></arg></host>
        """
        return cmd

    def cmd_read_efuse(self):
        content = {
            "arg": [
                "<target_file>ms-appdata:///local/efuse.xml</target_file>"
            ]
        }
        cmd = self.create_cmd("READ-EFUSE", content)
        # resp =
        """
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version>
        <command>CMD:UPLOAD-FILE</command><arg><"checksum>CHK_NO</checksum><info>%s</info>
        <target_file>%s</target_file><packet_length>0x%x</packet_length></arg></host>
        OK@0x%x (length)
        """
        return cmd

    def cmd_get_dev_info(self, host_mem_offset=0x8000000, length=0x100000):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
            <version>1.0</version>
            <command>CMD:SECURITY-GET-DEV-FW-INFO</command>
            <arg>
                <target_file>MEM://0x8000000:0x100000</target_file>
            </arg>
        </da>
        """
        content = {
            "arg": [
                f"<target_file>MEM://{hex(host_mem_offset)}:{hex(length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("SECURITY-GET-DEV-FW-INFO", content)
        """
        resp:
        <?xml version="1.0" encoding="utf-8"?>
        <sla version="1.0">
                <rnd>xxxx</rnd>
                <hrid>xxxx</hrid>
                <socid>xxxx</socid>
        </sla>'
        """
        return cmd

    def cmd_get_hw_info(self, host_mem_offset=0x7fe83c138700, length=0x200000):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
            <version>1.0</version>
            <command>CMD:GET-HW-INFO</command>
            <arg>
                <target_file>MEM://0x7fe83c138700:0x200000</target_file>
            </arg>
        </da>
        """
        content = {
            "arg": [
                f"<target_file>MEM://{hex(host_mem_offset)}:{hex(length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("GET-HW-INFO", content)
        # resp =
        """ #EMMC
        <?xml version=\"1.0\" encoding=\"utf-8\"?><da_hw_info><version>1.2</version><ram_size>0x%llx</ram_size>
        <battery_voltage>%d</battery_voltage><random_id>%s</random_id><storage>%s</storage><emmc>
        <block_size>0x%x</block_size><boot1_size>0x%llx</boot1_size><boot2_size>0x%llx</boot2_size>
        <rpmb_size>0x%llx</rpmb_size><user_size>0x%llx</user_size><gp1_size>0</gp1_size><gp2_size>0</gp2_size>
        <gp3_size>0</gp3_size><gp4_size>0</gp4_size><id>%s</id></emmc><product_id>%s</product_id></da_hw_info>
        or #UFS
        <?xml version=\"1.0\" encoding=\"utf-8\"?><da_hw_info><version>1.2</version><ram_size>0x%llx</ram_size>
        <battery_voltage>%d</battery_voltage><random_id>%s</random_id><storage>%s</storage><ufs>
        <block_size>0x%x</block_size><lua0_size>0x%llx</lua0_size><lua1_size>0x%llx</lua1_size>
        <lua2_size>0x%llx</lua2_size><lua3_size>0</lua3_size"><id>%s</id><ufs_vendor_id>0x%x</ufs_vendor_id>
        <ufs_cid>%s</ufs_cid><ufs_fwver>%s</ufs_fwver></ufs><product_id>%s</product_id></da_hw_info>
        or #NAND
        <?xml version=\"1.0\" encoding=\"utf-8\"?><da_hw_info><version>1.2</version><ram_size>0x%llx</ram_size>
        <battery_voltage>%d</battery_voltage><random_id>%s</random_id><storage>%s</storage><nand>
        <block_size>0x%x</block_size><page_size>0x%x</page_size><spare_size>0x%x</spare_size>
        <total_size>0x%llx</total_size><id>%s</id><page_parity_size>0x%x</page_parity_size><sub_type>%s</sub_type>
        </nand><product_id>%s</product_id></da_hw_info>
        or #NONE
        <?xml version=\"1.0\" encoding=\"utf-8\"?><da_hw_info><version>1.0</version><ram_size>0x%llx</ram_size>
        <battery_voltage>%d</battery_voltage><random_id>%s</random_id><storage>%s</storage></da_hw_info>
        """
        return cmd

    def cmd_set_boot_mode(self, mode: BootModes = BootModes.testmode, adb: bool = True, mobilelog: bool = True,
                          connectuart: bool = False):
        connect_type = "UART" if connectuart else "USB"
        mobilelog = "ON" if mobilelog else "OFF"
        adb = "ON" if adb else "OFF"
        content = {
            "arg": [
                f"<mode>{mode}</mode>",
                f"<connect_type>{connect_type}</connect_type>",
                f"<mobile_log>{mobilelog}</mobile_log>",
                f"<adb>{adb}</adb>"
            ]
        }
        cmd = self.create_cmd("SET-BOOT-MODE", content)
        return cmd

    def cmd_read_reg(self, bit_width: int = 32, base_address: int = 0x1000, mem_offset: int = 0x8000000,
                     mem_length: int = 0x4):
        content = {
            "arg": [
                f"<bit_width>{bit_width}</bit_width>",
                f"<base_address>{hex(base_address)}</base_address>",
                f"<target_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("READ-REGISTER", content)
        return cmd

    def cmd_write_reg(self, bit_width: int = 32, base_address: int = 0x1000, mem_offset: int = 0x8000000,
                      mem_length: int = 0x4):
        content = {
            "arg": [
                f"<bit_width>{bit_width}</bit_width>",
                f"<base_address>{hex(base_address)}</base_address>",
                f"<source_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</source_file>"
            ]
        }
        cmd = self.create_cmd("WRITE-REGISTER", content)
        return cmd

    @staticmethod
    def cmd_read_partition_name():
        cmd = ""
        return cmd

    @staticmethod
    def cmd_debug_ufs():
        cmd = ""
        return cmd

    def cmd_emmc_control(self, function: str = "GET-RPMB-STATUS", mem_offset=0x7fe83c338710, mem_length=0x200000):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
            <version>1.0</version>
            <command>CMD:EMMC-CONTROL</command>
            <arg>
                <function>LIFE-CYCLE-STATUS</function>
                <target_file>MEM://0x7fe83c338710:0x200000</target_file>
            </arg>
        </da>
        """
        content = {
            "arg": [
                f"<function>{function}</function>",
                f"<target_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("EMMC-CONTROL", content)
        return cmd

    def cmd_reboot(self, disconnect: bool = False):
        if disconnect:
            action = "DISCONNECT"
        else:
            action = "IMMEDIATE"
        content = {
            "arg": [
                f"<action>{action}</action>",
            ]
        }
        cmd = self.create_cmd("REBOOT", content)
        return cmd

    def cmd_write_partition(self, partition: str = "system", mem_offset: int = 0x8000000, mem_length: int = 0x100000):
        content = {
            "arg": [
                f"<partition>{partition}</partition>",
                f"<source_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</source_file>"
            ]
        }
        cmd = self.create_cmd("WRITE-FLASH", content)
        return cmd

    def cmd_write_flash(self, partition: str = "EMMC-USER", offset: int = 0, mem_offset: int = 0x8000000,
                        mem_length: int = 0x100000):
        content = {
            "arg": [
                f"<partition>{partition}</partition>",
                f"<offset>{hex(offset)}</offset>",
                f"<source_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</source_file>"
            ]
        }
        cmd = self.create_cmd("WRITE-FLASH", content)
        return cmd

    def cmd_read_partition(self, partition: str = "system"):
        content = {
            "arg": [
                f"<partition>{partition}</partition>",
                "<target_file>\"C:/file.bin\"</target_file>"
            ]
        }
        cmd = self.create_cmd("READ-PARTITION", content)
        return cmd

    def cmd_read_flash(self, partition: str = "EMMC-USER", offset: int = 0, length: int = 0x100000):
        content = {
            "arg": [
                f"<partition>{partition}</partition>",
                f"<offset>{hex(offset)}</offset>",
                f"<length>{hex(length)}</length>",
                "<target_file>ROM_0</target_file>"
            ]
        }
        cmd = self.create_cmd("READ-FLASH", content)
        return cmd

    def cmd_flash_all(self):
        content = {
            "arg": [
                "<path_separator>/</path_separator>",
                "<source_file>D:/scatter.xml</source_file>"
            ]
        }
        cmd = self.create_cmd("FLASH-ALL", content)
        return cmd

    def cmd_erase_partition(self, partition: str = "system"):
        content = {
            "arg": [
                f"<partition>{partition}</partition>"
            ]
        }
        cmd = self.create_cmd("ERASE-PARTITION", content)
        return cmd

    def cmd_erase_flash(self, partition: str = "EMMC-USER", offset: int = 0, length: int = 0x100000):
        content = {
            "arg": [
                f"<partition>{partition}</partition>",
                f"<offset>{hex(offset)}</offset>",
                f"<length>{hex(length)}</length>"
            ]
        }
        cmd = self.create_cmd("ERASE-FLASH", content)
        return cmd

    def cmd_flash_update(self):
        content = {
            "arg": [
                "<path_separator>/</path_separator>",
                "<source_file>D:/scatter.xml</source_file>",
                "<backup_folder>D:/backup</backup_folder>"
            ]
        }
        cmd = self.create_cmd("FLASH-UPDATE", content)
        return cmd

    def cmd_write_partitions(self, partitions):
        flashlist = ""
        for partition in partitions:
            flashlist += f"    <pt name={partition}>{partition}.img</pt>\n"
        content = {
            "arg": [
                "<source_file>D:/scatter.xml</source_file>",
                f"<flash_list>{flashlist}</flash_list>"
            ]
        }
        cmd = self.create_cmd("WRITE-PARTITIONS", content)
        return cmd

    def cmd_set_rsc(self, key: str = "k6885v1_64[op01]"):
        # runtime_switchable_config
        content = {
            "arg": [
                f"<key>{key}</key>",
                "<source_file>ms-appdata:///local/RSC.bin</source_file>"
            ]
        }
        cmd = self.create_cmd("SET-RSC", content)
        return cmd

    def cmd_write_private_cert(self):
        content = {
            "arg": [
                "<source_file>ms-appdata:///local/cert.bin</source_file>"
            ]
        }
        cmd = self.create_cmd("WRITE-PRIVATE-CERT", content)
        return cmd

    def cmd_get_da_info(self, mem_offset: int = 0x2000000, mem_length: int = 0x20000):
        content = {
            "arg": [
                f"<target_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("GET-DA-INFO", content)
        # resp =
        """
        <?xml version=\"1.0\" encoding=\"utf-8\"?><host><version>1.0</version>
        <command>CMD:UPLOAD-FILE</command><arg><checksum>CHK_NO</checksum><info>WriteLocalFile</info>
        <target_file>%s</target_file><packet_length>0x%x</packet_length></arg></host>
        <?xml version=\"1.0\" encoding=\"utf-8\"?><da_info><version>1.0</version>
        <da_version>2021</da_version><build>May 24 2022:19:03:56</build></da_info>"
        OK
        OK@0x%x
        """
        return cmd

    def cmd_get_sys_property(self, key="DA.SLA", host_mem_offset: int = 0x7fe83c138700, length=0x200000):
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da>
            <version>1.0</version>
            <command>CMD:GET-SYS-PROPERTY</command>
            <arg>
                <key>DA.SLA</key>
                <target_file>MEM://0x7fe83c138700:0x200000</target_file>
            </arg>
        </da>
        """
        content = {
            "arg": [
                f"<key>{key}</key>",
                f"<target_file>MEM://{hex(host_mem_offset)}:{hex(length)}</target_file>"
            ]
        }
        cmd = self.create_cmd("GET-SYS-PROPERTY", content)
        return cmd

    def cmd_set_host_info(self, hostinfo: str = ""):
        """
        <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
        <command>CMD:SET-HOST-INFO</command>
        <arg><info>20230901T234721</info></arg>
        """
        if hostinfo == "":
            current_date_and_time = datetime.datetime.now()
            hostinfo = current_date_and_time.strftime("%Y%m%dT%H%M%S")
        content = {
            "arg": [
                f"<info>{hostinfo}</info>",
            ]
        }
        cmd = self.create_cmd("SET-HOST-INFO", content)
        return cmd

    def cmd_get_downloaded_image_feedback(self, mem_offset: int = 0x2000000, mem_length: int = 0x20000):
        content = {
            "arg": [
                f"<target_file>MEM://{hex(mem_offset)}:{hex(mem_length)}</target_file>",
            ]
        }
        cmd = self.create_cmd("GET-DOWNLOADED-IMAGE-FEEDBACK", content)
        return cmd
