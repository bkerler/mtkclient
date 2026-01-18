## Usage

### Using MTKTools via the graphical user interface:
For the 'basics' you can use the GUI interface. This supports dumping partitions or the full flash for now. Run the following command:
```shell
python mtk_gui.py
```

### Using brom mode exploit :
```shell
python mtk.py --preloader [preloader]
```

Dump preloader via

```shell
python mtk.py dumppreloader
```

alternatively take the preloader from firmware

### Using preloader mode exploit :
```shell
python mtk.py --loader [MTK_AllInOne.bin or DA_BR.bin or DALoader]
```

and for Xiaomi 13C using unpatched loader:

```shell
python mtk.py --loader [MTK_AllInOne.bin or DA_BR.bin or DALoader] --stock
```

### Using stock mtk functionality without exploits :
```shell
python mtk.py --stock
```

### List supported devices (here: show only Xiaomi devices) :
```shell
python mtk.py devices --filter Xiaomi
```

### Run multiple commands
```shell
python mtk.py script examples/run.example
```
or
```shell
python mtk.py multi "cmd1;cmd2"
```
See the file "[run.example](https://github.com/bkerler/mtkclient/blob/main/examples/run.example)" on how to structure the script file

### Root the phone (Tested with android 9 - 12)

1. Dump boot and vbmeta
```shell
python mtk.py r boot,vbmeta boot.img,vbmeta.img
```

2. Reboot the phone
```shell
python mtk.py reset
```

3. Download patched magisk for mtk:
Download latest Magisk [here](https://github.com/topjohnwu/Magisk/releases/latest)

4. Install on target phone
- you need to enable usb-debugging via Settings/About phone/Version, Tap 7x on build number
- Go to Settings/Additional settings/Developer options, enable "OEM unlock" and "USB Debugging"
- Install magisk apk
```shell
adb install app-release.apk
```
- accept auth rsa request on mobile screen of course to allow adb connection

5. Upload boot to /sdcard/Download
```shell
adb push boot.img /sdcard/Download
```

6. Start magisk, tap on Install, select boot.img from /sdcard/Download, then:
```shell
adb pull /sdcard/Download/[displayed magisk patched boot filename here]
mv [displayed magisk patched boot filename here] boot.patched
```

7. Do the steps needed in section "Unlock bootloader below"

8. Flash magisk-patched boot and disable verity + verification on vbmeta
```shell
python mtk.py da vbmeta 3
python mtk.py w boot boot.patched
```

9. Reboot the phone
```shell
python mtk.py reset
```

10. Disconnect usb cable and enjoy your rooted phone :)


### Boot to meta mode via payload

Example:

```shell
python mtk.py payload --metamode FASTBOOT
```

### Dump preloader
```shell
mtk.py r preloader preloader.bin --parttype boot1
```

### Dump serialnumber / special partition
```shell
mtk.py r preloader preloader.bin --parttype boot2
```

### Read efuses

Example:

```shell
python mtk.py da efuse
```

### Unlock bootloader

1. Erase metadata and userdata (and md_udc if existing):
```shell
python mtk.py e metadata,userdata,md_udc
```

2. Unlock bootloader:
```shell
python mtk.py da seccfg unlock
```
for relocking use:
```shell
python mtk.py da seccfg lock
```

3. Reboot the phone:
```shell
python mtk.py reset
```

and disconnect usb cable to let the phone reboot.

If you are getting a dm-verity error on Android 11, just press the power button,
then the device should boot and show a yellow warning about unlocked bootloader and
then the device should boot within 5 seconds.


### Read flash

Dump boot partition to filename boot.bin via preloader

```shell
python mtk.py r boot boot.bin
```

Dump boot partition to filename boot.bin via bootrom

```shell
python mtk.py r boot boot.bin [--preloader=Loader/Preloader/your_device_preloader.bin]
```


Dump preloader partition to filename preloader.bin via bootrom

```shell
python mtk.py r preloader preloader.bin --parttype=boot1 [--preloader=Loader/Preloader/your_device_preloader.bin]
```

Read full flash to filename flash.bin (use --preloader for brom)

```shell
python mtk.py rf flash.bin
```

Read full flash to filename flash.bin (use --preloader for brom) for IoT devices (MT6261/MT2301):

```shell
python mtk.py rf flash.bin --iot
```

Read flash offset 0x128000 with length 0x200000 to filename flash.bin (use --preloader for brom)

```shell
python mtk.py ro 0x128000 0x200000 flash.bin
```

Dump all partitions to directory "out". (use --preloader for brom)

```shell
python mtk.py rl out
```

Show gpt (use --preloader for brom)

```shell
python mtk.py printgpt
```


Mount the flash as a filesystem

```shell
python mtk.py fs /mnt/mtk
```

### Write flash
(use --preloader for brom)

Write filename boot.bin to boot partition

```shell
python mtk.py w boot boot.bin
```

Write filename flash.bin as full flash (currently only works in da mode)

```shell
python mtk.py wf flash.bin
```

Write all files in directory "out" to the flash partitions

```shell
python mtk.py wl out
```

write file flash.bin to flash offset 0x128000 with length 0x200000 (use --preloader for brom)

```shell
python mtk.py wo 0x128000 0x200000 flash.bin
```

### Erase flash

Erase boot partition
```shell
python mtk.py e boot
```

Erase boot sectors
```shell
python mtk.py es boot [sector count]
```

### DA commands:

Peek memory
```shell
python mtk.py da peek [addr in hex] [length in hex] [optional: -filename filename.bin for reading to file]
```

Poke memory
```shell
python mtk.py da poke [addr in hex] [data as hexstring or -filename for reading from file]
```

Read rpmb (Only xflash for now)
```shell
python mtk.py da rpmb r [will read to rpmb.bin]
```

Write rpmb [Currently broken, xflash only]
```shell
python mtk.py da rpmb w filename
```

Generate and display rpmb1-3 key
```shell
python mtk.py da generatekeys
```

Unlock / Lock bootloader
```shell
python mtk.py da seccfg [lock or unlock]
```

---------------------------------------------------------------------------------------------------------------

### Bypass SLA, DAA and SBC (using generic_patcher_payload)
``shell
python mtk.py payload
``
If you want to use SP Flash tool afterwards, make sure you select "UART" in the settings, not "USB".

### Dump preloader
- Device has to be in bootrom mode and preloader has to be intact on the device
```shell
python mtk.py dumppreloader [--ptype=["amonet","kamakiri","kamakiri2","hashimoto"]] [--filename=preloader.bin]
```

### Dump brom
- Device has to be in bootrom mode, or da mode has to be crashed to enter damode
- if no option is given, either kamakiri or da will be used (da for insecure targets)
- if "kamakiri" is used as an option, kamakiri is enforced
- Valid options are : "kamakiri" (via usb_ctrl_handler attack), "amonet" (via gcpu)
  and "hashimoto" (via cqdma)

```shell
python mtk.py dumpbrom --ptype=["amonet","kamakiri","hashimoto"] [--filename=brom.bin]
```

For to dump unknown bootroms, use brute option :
```shell
python mtk.py brute
```
If it's successful, please add an issue over here and append the bootrom in order to add full support.

---------------------------------------------------------------------------------------------------------------

### Crash da in order to enter brom

```shell
python mtk.py crash [--vid=vid] [--pid=pid] [--interface=interface]
```

### Read memory using patched preloader
- Boot in Brom or crash to Brom
```shell
python mtk.py peek [addr] [length] --preloader=patched_preloader.bin
```

### Run custom payload

```shell
python mtk.py payload --payload=payload.bin [--var1=var1] [--wdt=wdt] [--uartaddr=addr] [--da_addr=addr] [--brom_addr=addr]
```

---------------------------------------------------------------------------------------------------------------
## Stage2 usage
### Run python mtk.py stage (brom) or mtk plstage (preloader)

#### Run stage2 in bootrom
``shell
python mtk.py stage
``

#### Run stage2 in preloader
``shell
python mtk.py plstage
``

#### Run stage2 plstage in bootrom
- Boot in Brom or crash to Brom
```shell
python mtk.py plstage --preloader=preloader.bin
```

### Use stage2 tool


### Leave stage2 and reboot
``shell
python stage2.py reboot
``

### Read rpmb in stage2 mode
``shell
python stage2.py rpmb
``

### Read preloader in stage2 mode
``shell
python stage2.py preloader
``

### Read memory as hex data in stage2 mode
``shell
python stage2.py memread [start addr] [length]
``

### Read memory to file in stage2 mode
``shell
python stage2.py memread [start addr] [length] --filename filename.bin
``

### Write hex data to memory in stage2 mode
``shell
python stage2.py memwrite [start addr] --data [data as hexstring]
``

### Write memory from file in stage2 mode
``shell
python stage2.py memwrite [start addr] --filename filename.bin
``

### Extract keys
``shell
python stage2.py keys --mode [sej, dxcc]
``
For dxcc, you need to use plstage instead of stage
