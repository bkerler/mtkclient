#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2025
# Licensed under GPLv3 License
#
# Minimal i18n layer for the user-facing surfaces of mtkclient:
#   * CLI help texts and messages (mtk.py)
#   * hardcoded GUI strings (mtk_gui.py)
#
# Design notes:
#   * po-like flat dictionaries: the English source string is the key, so
#     call sites never break on missing keys (passthrough instead).
#   * Activation: --lang <code> (CLI) or the MTK_LANG environment variable.
#     The default language is "en", which returns every string unchanged —
#     upstream behavior is fully preserved unless the user opts in.
#   * Unknown language codes fall back to "en" with a warning on stderr.
#   * Internal library messages (mtkclient/Library/) intentionally stay in
#     English to keep this change minimal and mergeable. The GUI dialogs
#     already ship a Qt Linguist (.ts/.qm) system in mtkclient/gui/i18n/;
#     this layer activates those translations for the chosen language too.

import os
import sys

DEFAULT_LANG = "en"
SUPPORTED_LANGS = (DEFAULT_LANG, "ru")
LANG_ENV_VAR = "MTK_LANG"

_current_lang = DEFAULT_LANG


def get_lang():
    """Return the currently active language code."""
    return _current_lang


def set_lang(lang):
    """Set the active language. Unknown values fall back to English."""
    global _current_lang
    if lang in SUPPORTED_LANGS:
        _current_lang = lang
    else:
        _warn_unknown_lang(lang)
        _current_lang = DEFAULT_LANG
    return _current_lang


def _warn_unknown_lang(lang):
    print(f"[mtkclient] i18n: unknown language {lang!r}, falling back to English",
          file=sys.stderr)


def activate(argv=None, env=None):
    """Detect the interface language before any parser or widget is built.

    Precedence: --lang in argv > MTK_LANG environment variable > default ("en").
    Unknown values fall back to English. Returns the active language code.
    """
    environment = env if env is not None else os.environ
    if argv:
        for i, arg in enumerate(argv):
            if arg == "--lang" and i + 1 < len(argv):
                _apply(argv[i + 1])
                return _current_lang
            if arg.startswith("--lang="):
                _apply(arg.split("=", 1)[1])
                return _current_lang
    from_env = environment.get(LANG_ENV_VAR)
    if from_env:
        _apply(from_env)
    return _current_lang


def normalize_lang(value):
    """Normalize a language code (strip surrounding whitespace, lowercase)."""
    return value.strip().lower()


def _apply(value):
    global _current_lang
    lang = normalize_lang(value)
    if lang in SUPPORTED_LANGS:
        _current_lang = lang
    else:
        _warn_unknown_lang(value)


def t(text):
    """Translate a user-facing string.

    Returns the source string unchanged for the default language ("en") or
    when no translation exists for the active language (po-like passthrough),
    so a missing key can never break a call site.
    """
    if _current_lang == DEFAULT_LANG:
        return text
    table = _TRANSLATIONS.get(_current_lang)
    if not table:
        return text
    return table.get(text, text)


_TRANSLATIONS = {
    "ru": {
        # ================= CLI: command help (mtk.py, CMDS_HELP) =================
        "Print GPT Table information": "Показать информацию о таблице GPT",
        "Save gpt table to given directory": "Сохранить таблицу GPT в указанный каталог",
        "Read flash to filename": "Прочитать flash в файл",
        "Read all partitions from flash to a directory": "Прочитать все разделы из flash в каталог",
        "Read whole flash to file": "Прочитать весь flash в файл",
        "Read sectors starting at start_sector to filename": "Прочитать сектора начиная с start_sector в файл",
        "Read flash starting at offset to filename": "Прочитать flash начиная с offset в файл",
        "Mount the device as a FUSE filesystem": "Смонтировать устройство как файловую систему FUSE",
        "Write partition from filename": "Записать раздел из файла",
        "Write flash from filename": "Записать flash из файла",
        "Write partitions from directory path to flash": "Записать разделы из каталога во flash",
        "Write flash starting at offset from filename": "Записать flash начиная с offset из файла",
        "Erase partition": "Стереть раздел",
        "Erase partition with sector count": "Стереть раздел с указанием числа секторов",
        "Erase sector with sector count": "Стереть сектора с указанием их числа",
        "Read crypto footer from flash": "Прочитать крипто-footer из flash",
        "Send mtk reset command": "Отправить команду reset (mtk)",
        "Switch to meta mode": "Переключиться в meta-режим",
        "Switch to meta mode (wdt)": "Переключиться в meta-режим (wdt)",
        "Try to dump the bootrom": "Попытаться сдампить BROM",
        "Try to dump the sram": "Попытаться сдампить SRAM",
        "Try to dump the preloader": "Попытаться сдампить preloader",
        "Run a specific kamakiri / da payload": "Запустить указанный payload (kamakiri / da)",
        "Try to crash the preloader": "Попытаться уронить preloader (crash)",
        "Bruteforce the kamakiri var1": "Брутфорс var1 для kamakiri",
        "Get target config (sbc, daa, etc.)": "Получить конфигурацию цели (sbc, daa и др.)",
        "Get target logs": "Получить логи цели",
        "Read memory in patched preloader mode": "Чтение памяти в режиме пропатченного preloader",
        "Run stage2 payload via boot rom mode (kamakiri)": "Запустить payload stage2 через режим bootrom (kamakiri)",
        "Run stage2 payload via preloader mode (send_da)": "Запустить payload stage2 через режим preloader (send_da)",
        "Run da xflash/legacy special commands": "Специальные команды DA (xflash/legacy)",
        "Run multiple commands using text script": "Выполнить несколько команд из текстового сценария",
        "Run multiple commands using semicolon-separated list": "Выполнить несколько команд из списка через точку с запятой",
        "List supported devices": "Список поддерживаемых устройств",
        # ================= CLI: argument group titles =================
        "Connection & Interface": "Подключение и интерфейс",
        "Authentication": "Аутентификация",
        "Debug & Sector": "Отладка и сектора",
        "Bootrom / Preloader Exploit": "Эксплойты BROM / preloader",
        "GPT & Partition": "GPT и разделы",
        "Language": "Язык",
        # ================= CLI: connection / auth / debug options =================
        "Use serial port (can be DETECT)": "Использовать последовательный порт (можно DETECT)",
        "use stock da": "использовать штатный DA",
        "Set uart log level (0=Trace, 2=Normal)": "Задать уровень uart-логов (0=Trace, 2=Normal)",
        "Set log channel (\"UART\",\"USB\", \"BOTH\")": "Задать канал логов (\"UART\",\"USB\", \"BOTH\")",
        "Set log level (0=Trace, 2=Normal)": "Задать уровень логов (0=Trace, 2=Normal)",
        "Dump preloader to file": "Сдампить preloader в файл",
        "Derive HW keys": "Вывести аппаратные ключи (HW)",
        "Use special mode for iot MT6261/2301": "Специальный режим для IoT MT6261/2301",
        "Read Soc ID": "Прочитать Soc ID",
        "Use auth file (auth_sv5.auth)": "Использовать файл аутентификации (auth_sv5.auth)",
        "Use cert file": "Использовать файл сертификата",
        "Enable verbose mode": "Включить подробный режим",
        "Interface language (\"en\", \"ru\"). Default: \"en\" (or env MTK_LANG)":
            "Язык интерфейса (\"en\", \"ru\"). По умолчанию: \"en\" (или переменная окружения MTK_LANG)",
        # ================= CLI: exploit options =================
        "Use specific DA loader, disable autodetection": "Использовать указанный загрузчик DA, отключить автовыбор",
        "Set the preloader filename for dram config": "Имя файла preloader для конфигурации DRAM",
        "Payload type: amonet, kamakiri, kamakiri2, carbonara": "Тип payload: amonet, kamakiri, kamakiri2, carbonara",
        "Set kamakiri specific var1 value": "Задать значение var1 для kamakiri",
        "Set payload uart_addr value": "Задать значение uart_addr для payload",
        "Set a specific da payload addr": "Задать адрес payload для DA",
        "Set a specific brom payload addr": "Задать адрес payload для BROM",
        "Set a crash mode (0=dasend1,1=dasend2,2=daread)": "Задать режим crash (0=dasend1,1=dasend2,2=daread)",
        "Set a specific watchdog addr": "Задать адрес watchdog",
        "Skip wdt init": "Пропустить инициализацию wdt",
        "Enforce crash if device is in pl mode": "Форсировать crash, если устройство в режиме pl",
        "Use app id (hexstring)": "Использовать app id (hex-строка)",
        # ================= CLI: GPT / partition options =================
        "Set default sector size": "Задать размер сектора по умолчанию",
        "Set GPT entry count": "Задать число записей GPT",
        "Set GPT entry size": "Задать размер записи GPT",
        "Set GPT entry start lba sector": "Задать стартовый LBA-сектор записи GPT",
        "Partition type (user/boot1/rpmb/lu0 etc.)": "Тип раздела (user/boot1/rpmb/lu0 и др.)",
        "Skip partitions (comma separated names)": "Пропустить разделы (имена через запятую)",
        # ================= CLI: subcommand arguments =================
        "Partitions (comma sep)": "Разделы (через запятую)",
        "Output files (comma sep)": "Выходные файлы (через запятую)",
        "Offset to read from": "Смещение для чтения",
        "Length to read": "Длина чтения",
        "Input files (comma sep)": "Входные файлы (через запятую)",
        "Use a gpt file instead of trying to read gpt from flash": "Использовать файл GPT вместо чтения GPT из flash",
        "Directory path": "Путь к каталогу",
        "Flash image file": "Файл образа flash",
        "Byte offset": "Смещение в байтах",
        "Length": "Длина",
        "Disable internal flash read for iot MT6261/2301": "Отключить чтение внутреннего flash для IoT MT6261/2301",
        "Start sector": "Начальный сектор",
        "Sector count": "Число секторов",
        "Sectors count": "Число секторов",
        "Partition to erase": "Раздел для стирания",
        "File": "Файл",
        "Filename to store footer": "Имя файла для сохранения footer",
        "Mount as FUSE filesystem": "Смонтировать как файловую систему FUSE",
        "Send reset command": "Отправить команду reset",
        "Enter meta mode": "Войти в meta-режим",
        "Enter meta mode (wdt)": "Войти в meta-режим (wdt)",
        "Optional filename": "Необязательное имя файла",
        "Payload file (optional)": "Файл payload (необязательно)",
        "Address to read from memory": "Адрес для чтения из памяти",
        "Bytes to read from memory": "Число байт для чтения из памяти",
        "Save to file (optional)": "Сохранить в файл (необязательно)",
        "Verify if stage2 data has been written correctly": "Проверить корректность записи данных stage2",
        "Set stage2 filename": "Задать имя файла stage2",
        "Set stage2 loading address": "Задать адрес загрузки stage2",
        "Set stage1 loader filename": "Задать имя файла загрузчика stage1",
        "Option for plstage - Boot to (lk, tee1)": "Опция для plstage — загрузить в (lk, tee1)",
        "pl stage filename (optional)": "Имя файла pl stage (необязательно)",
        "metamode to use [off,usb,uart]": "Используемый metamode [off,usb,uart]",
        "Address to read from (hex value)": "Адрес для чтения (hex)",
        "Read efuses": "Прочитать efuse",
        "Generate keys": "Сгенерировать ключи",
        "Enable key server": "Включить сервер ключей",
        "MetaMode Tools": "Инструменты meta-режима",
        "Patch vbmeta partition": "Пропатчить раздел vbmeta",
        "vbmeta mode (0=locked, 1=disable_verity, 2=disable_verification, 3=disable verity+verification)":
            "Режим vbmeta (0=locked, 1=disable_verity, 2=disable_verification, 3=disable verity+verification)",
        "nvitem decryption/encryption": "Расшифровка/шифрование nvitem",
        "Encrypt": "Зашифровать",
        "seed": "Seed (начальное значение)",
        "aeskey": "AES-ключ",
        "patch modem for imei": "Патч модема для IMEI",
        "imei decryption/encryption": "Расшифровка/шифрование IMEI",
        "imeis, separated by ,": "IMEI через запятую",
        "productname": "Имя продукта",
        "Write": "Записать",
        "RPMB Tools": "Инструменты RPMB",
        "Commands: r w": "Команды: r w",
        "Read rpmb": "Прочитать RPMB",
        "Filename to write data into": "Файл для записи данных",
        "Start sector (offset/0x100 bytes)": "Начальный сектор (offset/0x100 байт)",
        "Write rpmb": "Записать RPMB",
        "Filename to write from": "Файл-источник данных",
        "Erase rpmb": "Стереть RPMB",
        "Auth rpmbkey": "Аутентификация rpmb-ключом",
        "rpmb key (hexstring, 32 bytes)": "Ключ rpmb (hex-строка, 32 байта)",
        "Dump whole memory areas": "Дамп всех областей памяти",
        "Directory to dump ram dump files": "Каталог для дампов памяти",
        "Dump dram memory": "Дамп памяти DRAM",
        "Write memory": "Запись в память",
        "Data to write": "Данные для записи",
        "Unlock device / Configure seccfg": "Разблокировка устройства / настройка seccfg",
        "Needed flag (unlock,lock)": "Требуемый флаг (unlock,lock)",
        "Retain legacy V4 behavior by updating the dm-verity state": "Сохранить legacy-поведение V4, обновив состояние dm-verity",
        "Optional Filter string": "Необязательная строка фильтра",
        # ================= GUI: hardcoded strings (mtk_gui.py) =================
        "Select Serial Port": "Выбор последовательного порта",
        "Refresh": "Обновить",
        "Cancel": "Отмена",
        "No serial ports found": "Последовательные порты не найдены",
        "View": "Вид",
        "Dark Mode": "Тёмная тема",
        "<b>Total:</b>": "<b>Всего:</b>",
        "<b>Current partition:</b>": "<b>Текущий раздел:</b>",
        "Bootrom mode": "Режим BROM",
        "DA mode": "Режим DA",
        "Preloader mode": "Режим preloader",
        "Phone detected:\n": "Обнаружено устройство:\n",
        "Done.": "Готово.",
        "DONE": "ГОТОВО",
        "Connection exception: {e}": "Исключение при подключении: {e}",
        "Progress update error: {e}": "Ошибка обновления прогресса: {e}",
    },
}
