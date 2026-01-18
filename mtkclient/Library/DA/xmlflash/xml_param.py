max_node_value_length = 256
max_address_length = 9
max_xml_data_length = 0x200000


class DataType:
    DT_PROTOCOL_FLOW = 1
    DT_MESSAGE = 2


class ChecksumAlgorithm:
    NONE = "NONE"
    USB = "USB"
    STORAGE = "STORAGE"
    USB_STORAGE = "USB-STORAGE"


class LogLevel:
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class LogChannel:
    USB = "USB"
    UART = "UART"


class BatterySetting:
    YES = "YES"
    NO = "NO"
    AUTO_DETECT = "AUTO-DETECT"


class FtSystemOSE:
    OS_WIN = "WINDOWS"
    OS_LINUX = "LINUX"
