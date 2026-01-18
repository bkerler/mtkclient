class Cmd:
    # COMMANDS
    DOWNLOAD_BLOADER_CMD = b"\x51"
    NAND_BMT_REMARK_CMD = b"\x52"

    SDMMC_SWITCH_PART_CMD = b"\x60"
    SDMMC_WRITE_IMAGE_CMD = b"\x61"
    SDMMC_WRITE_DATA_CMD = b"\x62"
    SDMMC_GET_CARD_TYPE = b"\x63"
    SDMMC_RESET_DIS_CMD = b"\x64"

    UFS_SWITCH_PART_CMD = b"\x80"
    UFS_WRITE_IMAGE_CMD = b"\x81"
    UFS_WRITE_DATA_CMD = b"\x82"
    UFS_READ_GPT_CMD = b"\x85"
    UFS_WRITE_GPT_CMD = b"\x89"

    UFS_OTP_CHECKDEVICE_CMD = b"\x8a"
    UFS_OTP_GETSIZE_CMD = b"\x8b"
    UFS_OTP_READ_CMD = b"\x8c"
    UFS_OTP_PROGRAM_CMD = b"\x8d"
    UFS_OTP_LOCK_CMD = b"\x8e"
    UFS_OTP_LOCK_CHECKSTATUS_CMD = b"\x8f"

    USB_SETUP_PORT = b"\x70"
    USB_LOOPBACK = b"\x71"
    USB_CHECK_STATUS = b"\x72"
    USB_SETUP_PORT_EX = b"\x73"

    # EFUSE
    READ_REG32_CMD = b"\x7A"
    WRITE_REG32_CMD = b"\x7B"
    PWR_READ16_CMD = b"\x7C"
    PWR_WRITE16_CMD = b"\x7D"
    PWR_READ8_CMD = b"\x7E"
    PWR_WRITE8_CMD = b"\x7F"

    DA_NWDM_INFO = b"\x80"

    EMMC_OTP_CHECKDEVICE_CMD = b"\x99"
    EMMC_OTP_GETSIZE_CMD = b"\x9A"
    EMMC_OTP_READ_CMD = b"\x9B"
    EMMC_OTP_PROGRAM_CMD = b"\x9C"
    EMMC_OTP_LOCK_CMD = b"\x9D"
    EMMC_OTP_LOCK_CHECKSTATUS_CMD = b"\x9E"

    WRITE_USB_DOWNLOAD_CONTROL_BIT_CMD = b"\xA0"
    WRITE_PARTITION_TBL_CMD = b"\xA1"
    READ_PARTITION_TBL_CMD = b"\xA2"
    READ_BMT = b"\xA3"
    SDMMC_WRITE_PMT_CMD = b"\xA4"
    SDMMC_READ_PMT_CMD = b"\xA5"
    READ_IMEI_PID_SWV_CMD = b"\xA6"
    READ_DOWNLOAD_INFO = b"\xA7"
    WRITE_DOWNLOAD_INFO = b"\xA8"
    SDMMC_WRITE_GPT_CMD = b"\xA9"
    NOR_READ_PTB_CMD = b"\xAA"
    NOR_WRITE_PTB_CMD = b"\xAB"

    NOR_BLOCK_INDEX_TO_ADDRESS = b"\xB0"  # deprecated
    NOR_ADDRESS_TO_BLOCK_INDEX = b"\xB1"  # deprecated
    NOR_WRITE_DATA = b"\xB2"  # deprecated
    NAND_WRITE_DATA = b"\xB3"
    SECURE_USB_RECHECK_CMD = b"\xB4"
    SECURE_USB_DECRYPT_CMD = b"\xB5"
    NFB_BL_FEATURE_CHECK_CMD = b"\xB6"  # deprecated
    NOR_BL_FEATURE_CHECK_CMD = b"\xB7"  # deprecated

    SF_WRITE_IMAGE_CMD = b"\xB8"  # deprecated

    # Android S-USBDL
    SECURE_USB_IMG_INFO_CHECK_CMD = b"\xB9"
    SECURE_USB_WRITE = b"\xBA"
    SECURE_USB_ROM_INFO_UPDATE_CMD = b"\xBB"
    SECURE_USB_GET_CUST_NAME_CMD = b"\xBC"
    SECURE_USB_CHECK_BYPASS_CMD = b"\xBE"
    SECURE_USB_GET_BL_SEC_VER_CMD = b"\xBF"
    # Android S-USBDL

    VERIFY_IMG_CHKSUM_CMD = b"\xBD"

    GET_BATTERY_VOLTAGE_CMD = b"\xD0"
    POST_PROCESS = b"\xD1"
    SPEED_CMD = b"\xD2"
    MEM_CMD = b"\xD3"
    FORMAT_CMD = b"\xD4"
    WRITE_CMD = b"\xD5"
    READ_CMD = b"\xD6"
    WRITE_REG16_CMD = b"\xD7"
    READ_REG16_CMD = b"\xD8"
    FINISH_CMD = b"\xD9"
    GET_DSP_VER_CMD = b"\xDA"
    ENABLE_WATCHDOG_CMD = b"\xDB"
    NFB_WRITE_BLOADER_CMD = b"\xDC"  # deprecated
    NAND_IMAGE_LIST_CMD = b"\xDD"
    NFB_WRITE_IMAGE_CMD = b"\xDE"
    NAND_READPAGE_CMD = b"\xDF"
    CHK_PC_SEC_INFO_CMD = b"\xE0"
    UPDATE_FLASHTOOL_CFG_CMD = b"\xE1"
    CUST_PARA_GET_INFO_CMD = b"\xE2"  # deprecated
    CUST_PARA_READ_CMD = b"\xE3"  # deprecated
    CUST_PARA_WRITE_CMD = b"\xE4"  # deprecated
    SEC_RO_GET_INFO_CMD = b"\xE5"  # deprecated
    SEC_RO_READ_CMD = b"\xE6"  # deprecated
    SEC_RO_WRITE_CMD = b"\xE7"  # deprecated
    ENABLE_DRAM = b"\xE8"
    OTP_CHECKDEVICE_CMD = b"\xE9"
    OTP_GETSIZE_CMD = b"\xEA"
    OTP_READ_CMD = b"\xEB"
    OTP_PROGRAM_CMD = b"\xEC"
    OTP_LOCK_CMD = b"\xED"
    OTP_LOCK_CHECKSTATUS_CMD = b"\xEE"
    GET_PROJECT_ID_CMD = b"\xEF"
    GET_FAT_INFO_CMD = b"\xF0"  # deprecated
    FDM_MOUNTDEVICE_CMD = b"\xF1"
    FDM_SHUTDOWN_CMD = b"\xF2"
    FDM_READSECTORS_CMD = b"\xF3"
    FDM_WRITESECTORS_CMD = b"\xF4"
    FDM_MEDIACHANGED_CMD = b"\xF5"
    FDM_DISCARDSECTORS_CMD = b"\xF6"
    FDM_GETDISKGEOMETRY_CMD = b"\xF7"
    FDM_LOWLEVELFORMAT_CMD = b"\xF8"
    FDM_NONBLOCKWRITESECTORS_CMD = b"\xF9"
    FDM_RECOVERABLEWRITESECTORS_CMD = b"\xFA"
    FDM_RESUMESECTORSTATES = b"\xFB"
    NAND_EXTRACT_NFB_CMD = b"\xFC"  # deprecated
    NAND_INJECT_NFB_CMD = b"\xFD"  # deprecated

    MEMORY_TEST_CMD = b"\xFE"
    ENTER_RELAY_MODE_CMD = b"\xFF"


class Rsp:
    SOC_OK = b"\xC1"
    SOC_FAIL = b"\xCF"
    SYNC_CHAR = b"\xC0"
    CONT_CHAR = b"\x69"
    STOP_CHAR = b"\x96"
    ACK = b"\x5A"
    NACK = b"\xA5"
    UNKNOWN_CMD = b"\xBB"


class PortValues:
    UART_BAUD_921600 = b'\x01',
    UART_BAUD_460800 = b'\x02',
    UART_BAUD_230400 = b'\x03',
    UART_BAUD_115200 = b'\x04',
    UART_BAUD_57600 = b'\x05',
    UART_BAUD_38400 = b'\x06',
    UART_BAUD_19200 = b'\x07',
    UART_BAUD_9600 = b'\x08',
    UART_BAUD_4800 = b'\x09',
    UART_BAUD_2400 = b'\x0a',
    UART_BAUD_1200 = b'\x0b',
    UART_BAUD_300 = b'\x0c',
    UART_BAUD_110 = b'\x0d'
