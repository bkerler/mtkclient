# MTKClient
![Logo](mtkclient/gui/images/logo_256.png)

Just some mtk tool for exploitation, reading/writing flash and doing crazy stuff.
For windows, you need to install the stock mtk port and the usbdk driver (see instructions below).
For linux, a patched kernel is only needed when using old kamakiri (see Setup folder) (except for read/write flash).

Once the mtk script is running, boot into brom mode by powering off device, press and hold either
vol up + power or vol down + power and connect the phone. Once detected by the tool,
release the buttons.

## MT6781, MT6789, MT6855, MT6886, MT6895, MT6983, MT8985
- These chipsets use a new protocol called V6 and the bootrom is patched, thus you need a valid da via --loader option.
- On some devices, preloader is deactivated, but you still use it by running "adb reboot edl".
- This only works with UNFUSED devices currently.
- For all devices with DAA, SLA and Remote-Auth activated no public solution currently exists (for various reasons).

## Credits
- kamakiri [xyzz]
- linecode exploit [chimera]
- Chaosmaster
- Geert-Jan Kreileman (GUI, design & fixes)
- All contributors

## Installation

### Use Re LiveDVD (everything ready to go, based on Ubuntu):
User: user, Password:user (based on Ubuntu 22.04 LTS)

[Live DVD V6](https://www.androidfilehost.com/?fid=1109791587270922802)


## Install

### Linux - (Ubuntu recommended, no patched kernel needed except for kamakiri)

#### Install python >=3.8, git and other deps

#### For Debian/Ubuntu
```
sudo apt install python3 git libusb-1.0-0 python3-pip libfuse2
```
#### For ArchLinux
```
(sudo) pacman -S  python python-pip python-pipenv git libusb fuse2
```
or
```
yay -S python python-pip git libusb fuse2
```

#### For Fedora
```
sudo dnf install python3 git libusb1 fuse
```

#### Grab files
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
pip3 install -r requirements.txt
pip3 install .
```

### Using venv
```
python3 -m venv ~/.venv
git clone https://github.com/bkerler/mtkclient
cd mtkclient
. ~/.venv/bin/activate
pip install -r requirements.txt
pip install .
```

#### Install rules
```
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER
sudo cp mtkclient/Setup/Linux/*.rules /etc/udev/rules.d
sudo udevadm control -R
sudo udevadm trigger
```
Make sure to reboot after adding the user to dialout/plugdev. If the device
has a vendor interface 0xFF (like LG), make sure to add "blacklist qcaux" to
the "/etc/modprobe.d/blacklist.conf".

---------------------------------------------------------------------------------------------------------------

### macOS

#### Install brew, macFUSE, OpenSSL

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install macfuse openssl
```

You may need to **reboot**

#### Grab files
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
```

#### Create python 3.9 venv and install dependencies
```
python3.9 -m venv mtk_venv
source mtk_venv/bin/activate
pip3 install --pre --no-binary capstone capstone
pip3 install PySide6 libusb
pip3 install -r requirements.txt
```

---------------------------------------------------------------------------------------------------------------

### Windows

#### Install python + git
- Install python >= 3.9 and git
- If you install python from microsoft store, "python setup.py install" will fail, but that step isn't required.
- WIN+R ```cmd```

#### Install Winfsp (for fuse)
Download and install [here](https://winfsp.dev/rel/)

#### Grab files and install
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
pip3 install -r requirements.txt
```

#### Get latest UsbDk 64-Bit
- Install normal MTK Serial Port driver (or use default Windows COM Port one, make sure no exclamation is seen)
- Get usbdk installer (.msi) from [here](https://github.com/daynix/UsbDk/releases/) and install it
- Test on device connect using "UsbDkController -n" if you see a device with 0x0E8D 0x0003
- Works fine under Windows 10 and 11 :D

#### Building wheel issues (creds to @Oyoh-Edmond)
##### Download and Install the Build Tools:
    Go to the Visual Studio Build Tools [download](https://visualstudio.microsoft.com/visual-cpp-build-tools) page.
    Download the installer and run it.

###### Select the Necessary Workloads:
    In the installer, select the "Desktop development with C++" workload.
    Ensure that the "MSVC v142 - VS 2019 C++ x64/x86 build tools" (or later) component is selected.
    You can also check "Windows 10 SDK" if it’s not already selected.

###### Complete the Installation:
    Click on the "Install" button to begin the installation.
    Follow the prompts to complete the installation.
    Restart your computer if required.

---------------------------------------------------------------------------------------------------------------
### Use kamakiri (optional, only needed for mt6260 or older)

- For linux (kamakiri attack), you need to recompile your linux kernel using this kernel patch :
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev libdw-dev
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
cd pahole && mkdir build && cd build && cmake .. && make && sudo make install
sudo mv /usr/local/libdwarves* /usr/local/lib/ && sudo ldconfig
```

```
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-`uname -r`.tar.xz
tar xvf linux-`uname -r`.tar.xz
cd linux-`uname -r`
patch -p1 < ../Setup/kernelpatches/disable-usb-checks-5.10.patch
cp -v /boot/config-$(uname -r) .config
make menuconfig
make
sudo make modules_install
sudo make install
```

- These aren't needed for current ubuntu (as make install will do, just for reference):

```
sudo update-initramfs -c -k `uname -r`
sudo update-grub
```

See Setup/kernels for ready-to-use kernel setups


- Reboot

```
sudo reboot
```


---------------------------------------------------------------------------------------------------------------

## Usage

### Using MTKTools via the graphical user interface:
For the 'basics' you can use the GUI interface. This supports dumping partitions or the full flash for now. Run the following command:
```
python mtk_gui.py
```

### Using stock mtk functionality without exploits :
```
python mtk.py --stock
```

### Run multiple commands
```bash
python mtk.py script examples/run.example
```
or
```
python mtk.py multi "cmd1;cmd2"
```
See the file "[run.example](https://github.com/bkerler/mtkclient/blob/main/examples/run.example)" on how to structure the script file

### Using in on venv
Basically, you created a venv folder, so you need to use it to python find the right packages, and don't have any conflicts
```
. ~/.venv/bin/activate
```
You should see something like this...
```
(.venv) [user@hostname]$ 
```
This means you are on venv folder!

* Example comands below...

```
./mtk.py r boot,vbmeta boot.img,vbmeta.img
./mtk.py payload
./mtk.py reset
```
or simply
```
mtk r boot,vbmeta boot.img,vbmeta.img
mtk payload
mtk reset
```

### Root the phone (Tested with android 9 - 12)

1. Dump boot and vbmeta
```
python mtk.py r boot,vbmeta boot.img,vbmeta.img
```

2. Reboot the phone
```
python mtk.py reset
```

3. Download patched magisk for mtk:
Download latest Magisk [here](https://github.com/topjohnwu/Magisk/releases/latest)

4. Install on target phone
- you need to enable usb-debugging via Settings/About phone/Version, Tap 7x on build number
- Go to Settings/Additional settings/Developer options, enable "OEM unlock" and "USB Debugging"
- Install magisk apk
```
adb install app-release.apk
```
- accept auth rsa request on mobile screen of course to allow adb connection

5. Upload boot to /sdcard/Download
```
adb push boot.img /sdcard/Download
```

6. Start magisk, tap on Install, select boot.img from /sdcard/Download, then:
```
adb pull /sdcard/Download/[displayed magisk patched boot filename here]
mv [displayed magisk patched boot filename here] boot.patched
```

7. Do the steps needed in section "Unlock bootloader below"

8. Flash magisk-patched boot and disable verity + verification on vbmeta
```
python mtk.py da vbmeta 3
python mtk.py w boot boot.patched
```

9. Reboot the phone
```
python mtk.py reset
```

10. Disconnect usb cable and enjoy your rooted phone :)


### Boot to meta mode via payload

Example:

```
python mtk.py payload --metamode FASTBOOT
```

### Dump preloader
```
mtk.py r preloader preloader.bin --parttype boot1
```

### Dump serialnumber / special partition
```
mtk.py r preloader preloader.bin --parttype boot2
```

### Read efuses

Example:

```
python mtk.py da efuse
```

### Unlock bootloader

1. Erase metadata and userdata (and md_udc if existing):
```
python mtk.py e metadata,userdata,md_udc
```

2. Unlock bootloader:
```
python mtk.py da seccfg unlock
```
for relocking use:
```
python mtk.py da seccfg lock
```

3. Reboot the phone:
```
python mtk.py reset
```

and disconnect usb cable to let the phone reboot.

If you are getting a dm-verity error on Android 11, just press the power button,
then the device should boot and show a yellow warning about unlocked bootloader and
then the device should boot within 5 seconds.


### Read flash

Dump boot partition to filename boot.bin via preloader

```
python mtk.py r boot boot.bin
```

Dump boot partition to filename boot.bin via bootrom

```
python mtk.py r boot boot.bin [--preloader=Loader/Preloader/your_device_preloader.bin]
```


Dump preloader partition to filename preloader.bin via bootrom

```
python mtk.py r preloader preloader.bin --parttype=boot1 [--preloader=Loader/Preloader/your_device_preloader.bin]
```

Read full flash to filename flash.bin (use --preloader for brom)

```
python mtk.py rf flash.bin
```

Read full flash to filename flash.bin (use --preloader for brom) for IoT devices (MT6261/MT2301):

```
python mtk.py rf flash.bin --iot
```

Read flash offset 0x128000 with length 0x200000 to filename flash.bin (use --preloader for brom)

```
python mtk.py ro 0x128000 0x200000 flash.bin
```

Dump all partitions to directory "out". (use --preloader for brom)

```
python mtk.py rl out
```

Show gpt (use --preloader for brom)

```
python mtk.py printgpt
```


Mount the flash as a filesystem

```
python mtk.py fs /mnt/mtk
```

### Write flash
(use --preloader for brom)

Write filename boot.bin to boot partition

```
python mtk.py w boot boot.bin
```

Write filename flash.bin as full flash (currently only works in da mode)

```
python mtk.py wf flash.bin
```

Write all files in directory "out" to the flash partitions

```
python mtk.py wl out
```

write file flash.bin to flash offset 0x128000 with length 0x200000 (use --preloader for brom)

```
python mtk.py wo 0x128000 0x200000 flash.bin
```

### Erase flash

Erase boot partition
```
python mtk.py e boot
```

Erase boot sectors
```
python mtk.py es boot [sector count]
```

### DA commands:

Peek memory
```
python mtk.py da peek [addr in hex] [length in hex] [optional: -filename filename.bin for reading to file]
```

Poke memory
```
python mtk.py da poke [addr in hex] [data as hexstring or -filename for reading from file]
```

Read rpmb (Only xflash for now)
```
python mtk.py da rpmb r [will read to rpmb.bin]
```

Write rpmb [Currently broken, xflash only]
```
python mtk.py da rpmb w filename
```

Generate and display rpmb1-3 key
```
python mtk.py da generatekeys
```

Unlock / Lock bootloader
```
python mtk.py da seccfg [lock or unlock]
```

---------------------------------------------------------------------------------------------------------------

### Bypass SLA, DAA and SBC (using generic_patcher_payload)
``
python mtk.py payload
``
If you want to use SP Flash tool afterwards, make sure you select "UART" in the settings, not "USB".

### Dump preloader
- Device has to be in bootrom mode and preloader has to be intact on the device
```
python mtk.py dumppreloader [--ptype=["amonet","kamakiri","kamakiri2","hashimoto"]] [--filename=preloader.bin]
```

### Dump brom
- Device has to be in bootrom mode, or da mode has to be crashed to enter damode
- if no option is given, either kamakiri or da will be used (da for insecure targets)
- if "kamakiri" is used as an option, kamakiri is enforced
- Valid options are : "kamakiri" (via usb_ctrl_handler attack), "amonet" (via gcpu)
  and "hashimoto" (via cqdma)

```
python mtk.py dumpbrom --ptype=["amonet","kamakiri","hashimoto"] [--filename=brom.bin]
```

For to dump unknown bootroms, use brute option :
```
python mtk.py brute
```
If it's successful, please add an issue over here and append the bootrom in order to add full support.

---------------------------------------------------------------------------------------------------------------

### Crash da in order to enter brom

```
python mtk.py crash [--vid=vid] [--pid=pid] [--interface=interface]
```

### Read memory using patched preloader
- Boot in Brom or crash to Brom
```
python mtk.py peek [addr] [length] --preloader=patched_preloader.bin
```

### Run custom payload

```
python mtk.py payload --payload=payload.bin [--var1=var1] [--wdt=wdt] [--uartaddr=addr] [--da_addr=addr] [--brom_addr=addr]
```

---------------------------------------------------------------------------------------------------------------
## Stage2 usage
### Run python mtk.py stage (brom) or mtk plstage (preloader)

#### Run stage2 in bootrom
``
python mtk.py stage
``

#### Run stage2 in preloader
``
python mtk.py plstage
``

#### Run stage2 plstage in bootrom
- Boot in Brom or crash to Brom
```
python mtk.py plstage --preloader=preloader.bin
```

### Use stage2 tool


### Leave stage2 and reboot
``
python stage2.py reboot
``

### Read rpmb in stage2 mode
``
python stage2.py rpmb
``

### Read preloader in stage2 mode
``
python stage2.py preloader
``

### Read memory as hex data in stage2 mode
``
python stage2.py memread [start addr] [length]
``

### Read memory to file in stage2 mode
``
python stage2.py memread [start addr] [length] --filename filename.bin
``

### Write hex data to memory in stage2 mode
``
python stage2.py memwrite [start addr] --data [data as hexstring]
``

### Write memory from file in stage2 mode
``
python stage2.py memwrite [start addr] --filename filename.bin
``

### Extract keys
``
python stage2.py keys --mode [sej, dxcc]
``
For dxcc, you need to use plstage instead of stage

---------------------------------------------------------------------

### I have issues ....... please send logs and full console details !

- Run the mtk tool with --debugmode. Log will be written to log.txt (hopefully)

## Rules / Infos

### Chip details / configs
- Go to config/brom_config.py
- Unknown usb vid/pids for autodetection go to config/usb_ids.py
# [LEARNING_RESOURCES](https://github.com/bkerler/mtkclient/blob/main/learning_resources.md)
