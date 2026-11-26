## Использование

### Работа с MTKTools через графический интерфейс:
Для базовых операций можно использовать GUI. Пока он поддерживает снятие дампов разделов или всей флеш-памяти. Выполните команду:
```shell
python mtk_gui.py
```

### Использование эксплойта в режиме brom:
```shell
python mtk.py --preloader [preloader]
```

Снять дамп preloader:

```shell
python mtk.py dumppreloader
```

Переключение логирования с uart на usb, чтобы видеть больше деталей лога в DA (только XML):
```shell
python mtk.py printgpt --logchannel="USB"
```


либо возьмите preloader из прошивки

### Использование эксплойта в режиме preloader:
```shell
python mtk.py --loader [MTK_AllInOne.bin or DA_BR.bin or DALoader]
```

и для Xiaomi 13C с использованием непропатченного загрузчика:

```shell
python mtk.py --loader [MTK_AllInOne.bin or DA_BR.bin or DALoader] --stock
```

### Использование стокового функционала mtk без эксплойтов:
```shell
python mtk.py --stock
```

### Список поддерживаемых устройств (здесь: показать только устройства Xiaomi):
```shell
python mtk.py devices --filter Xiaomi
```

### Запуск нескольких команд
```shell
python mtk.py script examples/run.example
```
или
```shell
python mtk.py multi "cmd1;cmd2"
```
Как оформить файл со скриптом, смотрите в файле "[run.example](https://github.com/bkerler/mtkclient/blob/main/examples/run.example)"

### Получение root на телефоне (проверено на android 9 - 12)

1. Снимите дампы boot и vbmeta
```shell
python mtk.py r boot,vbmeta boot.img,vbmeta.img
```

2. Перезагрузите телефон
```shell
python mtk.py reset
```

3. Скачайте пропатченный magisk для mtk:
Свежий Magisk скачивайте [здесь](https://github.com/topjohnwu/Magisk/releases/latest)

4. Установка на целевой телефон
- нужно включить отладку по USB: Настройки/О телефоне/Версия, 7 раз нажмите на номер сборки
- Перейдите в Настройки/Расширенные настройки/Для разработчиков, включите «Разблокировка OEM» и «Отладка по USB»
- Установите apk magisk
```shell
adb install app-release.apk
```
- разумеется, подтвердите запрос rsa-авторизации на экране телефона, чтобы разрешить подключение adb
- на телефонах Xiaomi, если установка не удаётся, попробуйте выключить оптимизацию MIUI в разделе «Для разработчиков»,
  перезапустите телефон и попробуйте снова

5. Загрузите boot в /sdcard/Download
```shell
adb push boot.img /sdcard/Download
```

6. Запустите magisk, нажмите «Установить», выберите boot.img из /sdcard/Download, затем:
```shell
adb pull /sdcard/Download/[имя пропатченного magisk-ом boot-файла, показанное на экране]
mv [имя пропатченного magisk-ом boot-файла, показанное на экране] boot.patched
```

7. Выполните шаги из раздела «Разблокировка загрузчика» ниже

8. Прошейте пропатченный magisk-ом boot и отключите verity + verification на vbmeta
```shell
python mtk.py da vbmeta 3
python mtk.py w boot boot.patched
```

9. Перезагрузите телефон
```shell
python mtk.py reset
```

10. Отключите usb-кабель и пользуйтесь телефоном с root :)

### Порядок разблокировки для стокового mtk с android >=9
1. Разблокируйте seccfg
```shell
python mtk.py da seccfg unlock
```

2. Сотрите разделы userdata,metadata,md_udc,cache
```shell
python mtk.py e userdata,metadata,md_udc,cache
```

2. Отключите verity + verification на vbmeta
```shell
python mtk.py da vbmeta 3
```

### Загрузка в режим meta через payload

Пример:

```shell
python mtk.py payload --metamode FASTBOOT
```

### Снятие дампа preloader
```shell
mtk.py r preloader preloader.bin --parttype boot1
```

### Чтение серийного номера / особого раздела
```shell
mtk.py r preloader preloader.bin --parttype boot2
```

### Чтение efuse

Пример:

```shell
python mtk.py da efuse
```

### Разблокировка загрузчика

1. Сотрите metadata и userdata (и md_udc, если есть):
```shell
python mtk.py e metadata,userdata,md_udc
```

2. Разблокируйте загрузчик:
```shell
python mtk.py da seccfg unlock
```
для повторной блокировки используйте:
```shell
python mtk.py da seccfg lock
```

3. Перезагрузите телефон:
```shell
python mtk.py reset
```

и отключите usb-кабель, чтобы телефон перезагрузился.

Если на Android 11 появляется ошибка dm-verity, просто нажмите кнопку питания —
устройство должно загрузиться и показать жёлтое предупреждение о разблокированном загрузчике,
после чего телефон загрузится в течение 5 секунд.


### Чтение флеш-памяти

Снять дамп раздела boot в файл boot.bin через preloader

```shell
python mtk.py r boot boot.bin
```

Снять дамп раздела boot в файл boot.bin через bootrom

```shell
python mtk.py r boot boot.bin [--preloader=Loader/Preloader/your_device_preloader.bin]
```


Снять дамп раздела preloader в файл preloader.bin через bootrom

```shell
python mtk.py r preloader preloader.bin --parttype=boot1 [--preloader=Loader/Preloader/your_device_preloader.bin]
```

Прочитать всю флеш-память в файл flash.bin (для brom используйте --preloader)

```shell
python mtk.py rf flash.bin
```

Прочитать всю флеш-память в файл flash.bin (для brom используйте --preloader) для IoT-устройств (MT6261/MT2301):

```shell
python mtk.py rf flash.bin --iot
```

Прочитать флеш-память со смещения 0x128000 длиной 0x200000 в файл flash.bin (для brom используйте --preloader)

```shell
python mtk.py ro 0x128000 0x200000 flash.bin
```

Снять дампы всех разделов в каталог "out". (для brom используйте --preloader)

```shell
python mtk.py rl out
```

Показать gpt (для brom используйте --preloader)

```shell
python mtk.py printgpt
```


Смонтировать флеш-память как файловую систему

```shell
python mtk.py fs /mnt/mtk
```

### Запись во флеш-память
(для brom используйте --preloader)

Записать файл boot.bin в раздел boot

```shell
python mtk.py w boot boot.bin
```

Записать файл flash.bin как всю флеш-память (сейчас работает только в режиме da)

```shell
python mtk.py wf flash.bin
```

Записать все файлы из каталога "out" в разделы флеш-памяти

```shell
python mtk.py wl out
```

Записать файл flash.bin во флеш-память со смещения 0x128000 длиной 0x200000 (для brom используйте --preloader)

```shell
python mtk.py wo 0x128000 0x200000 flash.bin
```

### Форматирование (стирание) флеш-памяти

Стереть раздел boot
```shell
python mtk.py e boot
```

Стереть сектора раздела boot
```shell
python mtk.py es boot [число секторов]
```

### Команды DA:

Чтение памяти (peek)
```shell
python mtk.py da peek [адрес в hex] [длина в hex] [опционально: -filename filename.bin для записи в файл]
```

Запись в память (poke)
```shell
python mtk.py da poke [адрес в hex] [данные в виде hex-строки или -filename для чтения из файла]
```

Чтение rpmb (пока только xflash)
```shell
python mtk.py da rpmb r [прочитает в rpmb.bin]
```

Запись rpmb [сейчас сломано, только xflash]
```shell
python mtk.py da rpmb w filename
```

Сгенерировать и показать ключ rpmb1-3
```shell
python mtk.py da generatekeys
```

Разблокировать / заблокировать загрузчик
```shell
python mtk.py da seccfg [lock или unlock]
```

---------------------------------------------------------------------------------------------------------------

### Обход SLA, DAA и SBC (с помощью generic_patcher_payload)
``shell
python mtk.py payload
```
Если после этого хотите использовать SP Flash tool, убедитесь, что в настройках выбрано «UART», а не «USB».

### Снятие дампа preloader
- Устройство должно быть в режиме bootrom, preloader должен быть цел на устройстве
```shell
python mtk.py dumppreloader [--ptype=["amonet","kamakiri","kamakiri2","hashimoto"]] [--filename=preloader.bin]
```

### Снятие дампа brom
- Устройство должно быть в режиме bootrom, либо da-режим нужно уронить (crash), чтобы войти в da-режим
- если опция не указана, будет использован kamakiri или da (da для небезопасных целей)
- если указана опция "kamakiri", kamakiri применяется принудительно
- Допустимые опции: "kamakiri" (через атаку usb_ctrl_handler), "amonet" (через gcpu)
  и "hashimoto" (через cqdma)

```shell
python mtk.py dumpbrom --ptype=["amonet","kamakiri","hashimoto"] [--filename=brom.bin]
```

Для снятия дампов неизвестных bootrom используйте опцию brute:
```shell
python mtk.py brute
```
Если всё получилось, создайте issue [вот здесь](https://github.com/bkerler/mtkclient/issues) и приложите bootrom, чтобы добавить полную поддержку.

---------------------------------------------------------------------------------------------------------------

### Урон da для входа в brom

```shell
python mtk.py crash [--vid=vid] [--pid=pid] [--interface=interface]
```

### Чтение памяти с помощью пропатченного preloader
- Загрузитесь в brom или уроните до brom
```shell
python mtk.py peek [адрес] [длина] --preloader=patched_preloader.bin
```

### Запуск своего payload

```shell
python mtk.py payload --payload=payload.bin [--var1=var1] [--wdt=wdt] [--uartaddr=addr] [--da_addr=addr] [--brom_addr=addr]
```

---------------------------------------------------------------------------------------------------------------
## Использование stage2
### Выполните python mtk.py stage (brom) или mtk plstage (preloader)

#### Запуск stage2 в bootrom
``shell
python mtk.py stage
``

#### Запуск stage2 в preloader
``shell
python mtk.py plstage
``

#### Запуск stage2 plstage в bootrom
- Загрузитесь в brom или уроните до brom
```shell
python mtk.py plstage --preloader=preloader.bin
```

### Использование инструмента stage2


### Выход из stage2 и перезагрузка
``shell
python stage2.py reboot
``

### Чтение rpmb в режиме stage2
``shell
python stage2.py rpmb
``

### Чтение preloader в режиме stage2
``shell
python stage2.py preloader
``

### Чтение памяти как hex-данных в режиме stage2
``shell
python stage2.py memread [начальный адрес] [длина]
``

### Чтение памяти в файл в режиме stage2
``shell
python stage2.py memread [начальный адрес] [длина] --filename filename.bin
``

### Запись hex-данных в память в режиме stage2
``shell
python stage2.py memwrite [начальный адрес] --data [данные в виде hex-строки]
``

### Запись памяти из файла в режиме stage2
``shell
python stage2.py memwrite [начальный адрес] --filename filename.bin
``

### Извлечение ключей
``shell
python stage2.py keys --mode [sej, dxcc]
``
Для dxcc нужно использовать plstage вместо stage
