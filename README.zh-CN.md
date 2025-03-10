<div align="right">
  Language:
  <a title="English" href="./README.md">🇺🇸</a>
  🇨🇳
</div>

# MTKClient
![Logo](mtkclient/gui/images/logo_256.png)

这是一款用于联发科芯片的调试工具，支持读写分区、利用漏洞对设备进行底层操作。
在Windows系统下使用需要安装MTK串口驱动和UsbDk驱动（详见下方说明）。
在Linux系统下，如果你使用的是旧版的kamakiri内核则需要使用内核补丁（见Setup目录），但读写分区等操作则不需要补丁。

打开MTKClient, 在设备完全关机的情况下按住电源键、音量+、音量-进入Bootrom模式，待工具检测到设备后显示 Jump to 0xXXXXXX 时松手。

## MT6781, MT6789, MT6855, MT6886, MT6895, MT6983, MT8985
- 这些联发科处理器用的是 V6 协议且 Bootrom 漏洞已被修复，需通过 ``--loader`` 指定有效的 DA 文件。
- 部分设备的预引导程序 preloader 被禁用了，可以通过执行 ``adb reboot edl`` 来进入该模式。
- 当前仅支持未熔断的设备（UNFUSED）。
- 所有使用 DAA/SLA/远程认证 的设备目前均无解决方案。

## 致谢
- kamakiri [xyzz]
- linecode exploit [chimera]
- Chaosmaster
- Geert-Jan Kreileman (GUI 设计及优化)
- 所有贡献者

## 安装

### 使用 LiveDVD (基于 Ubuntu, 开箱即用):
用户: user, 密码: user (基于 Ubuntu 22.04 LTS)

[Live DVD V6](https://www.androidfilehost.com/?fid=1109791587270922802)


## 安装步骤

### Linux - (推荐使用 Ubuntu, kamakiri 需要修补内核)

#### 安装 python >=3.8, git 及其他依赖

#### Debian/Ubuntu
```
sudo apt install python3 git libusb-1.0-0 python3-pip libfuse2
```
#### ArchLinux
```
(sudo) pacman -S  python python-pip git libusb fuse2
```
或者
```
yay -S python python-pip git libusb fuse2
```

#### Fedora
```
sudo dnf install python3 git libusb1 fuse
```

#### 克隆仓库并安装依赖
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
pip3 install -r requirements.txt
pip3 install .
```

#### 配置 udev 规则
```
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER
sudo cp mtkclient/Setup/Linux/*.rules /etc/udev/rules.d
sudo udevadm control -R
sudo udevadm trigger
```
配置完后建议重启系统，若设备使用的是  0xFF 接口(例如 LG)，需在 ``/etc/modprobe.d/blacklist.conf`` 配置文件中添加 ``blacklist qcaux``。

---------------------------------------------------------------------------------------------------------------

### macOS

#### 安装 brew, macFUSE, OpenSSL

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install macfuse openssl
```

安装完后可能需要 **重启**

#### 克隆仓库
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
```

#### 创建 python 3.9 venv 并安装依赖
```
python3.9 -m venv mtk_venv
source mtk_venv/bin/activate
pip3 install --pre --no-binary capstone capstone
pip3 install PySide6 libusb
pip3 install -r requirements.txt
```

---------------------------------------------------------------------------------------------------------------

### Windows

#### 安装 python + git
- 安装 [python](https://www.python.org/downloads/) >= 3.9 and [git](https://git-scm.com/downloads/win)
- 通过按下 WIN+R 键, 输入 ```cmd``` 并回车来打开终端

### 安装 Winfsp（fuse）
点击[此处](https://winfsp.dev/rel/)下载并安装

#### 克隆仓库并安装 python 依赖
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
pip3 install -r requirements.txt
```

#### 下载最新的 UsbDk 64位 驱动
- 安装 MTK 串口驱动 (如果设备管理器里边没有显示感叹号则无需安装)
- 下载 [UsbDk驱动 安装程序（.msi）](https://github.com/daynix/UsbDk/releases/) 并手动安装。
- 在 Windows 10 和 11 系统上完美运行 :D

#### 解决编译 wheel 报错的问题 (感谢 @Oyoh-Edmond)
##### 下载并安装构建工具:
下载 [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools) 并运行。
    
###### 选择必要的构建组件包:
在安装程序中, 勾选 "使用 C++ 的桌面开发" 组件包和 "MSVC v142 - VS 2019 C++ x64/x86 build tools (或更高版本)"，或者你也可以使用 "Windows 10 SDK" 组件。
    
###### 完成安装:
点击 "安装" 按钮即可开始安装。

---------------------------------------------------------------------------------------------------------------
### 使用 kamakiri（可选，对于 mt6260 或更旧设备）

- 对于 linux (kamakiri 内核), 你需要使用以下补丁来重新编译内核:
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

- 注: Ubuntu 系统执行 make install 时已自动处理，此步骤仅作参考

```
sudo update-initramfs -c -k `uname -r`
sudo update-grub
```

你可以在 Setup/kernels 目录中找到开箱即用的内核配置方案。


- 重启

```
sudo reboot
```


---------------------------------------------------------------------------------------------------------------

## 使用方法

### 通过图形化界面来使用 MTKClient:
基础的读写分区或者是深刷操作可以用图形化界面来完成。运行以下命令打开图形化窗口:
```
python mtk_gui.py
```

### 使用没有利用漏洞的 MTK 功能:
```
python mtk.py --stock
```

### 执行脚本或命令
```bash
python mtk.py script examples/run.example
```
或
```
python mtk.py multi "cmd1;cmd2"
```
参考 "[run.example](https://github.com/bkerler/mtkclient/blob/main/examples/run.example)" 来编写脚本

### 获取 Root 权限 (测试支持 android 9 - 12)

1. 提取 boot、vbmeta 分区
```
python mtk.py r boot,vbmeta boot.img,vbmeta.img
```

2. 重启设备
```
python mtk.py reset
```

3. 下载 Magisk 面具:  
[点我](https://github.com/topjohnwu/Magisk/releases/latest)前往下载

4. 通过 ADB 在设备上安装
- 打开系统设置，进入关于
- 连续点击多次 **构建版本** 后直到显示类似 **你现在处于开发者模式** 的提示
- 在开发者选项下，启用 **OEM解锁**（解锁Bootloader需要） 和 **USB调试**
- 通过命令安装 Magisk 面具
```
adb install app-release.apk
```
- 此时设备上会出现 **是否允许调试** 的对话框，勾选 **总是允许** 后确认

5. 上传提取的 boot 镜像到 /sdcard/Download
```
adb push boot.img /sdcard/Download
```

6. 打开 Magisk 管理器, 点击 **安装**, 选择 /sdcard/Download 下载目录中的 boot.img 文件, 点击 **确认**，在修补完成之后将修补后的 magisk_patched-xxxxx.img 传回电脑
```
adb pull /sdcard/Download/[这里写面具修补后的镜像文件名称]
mv [这里写面具修补后的镜像文件名称] boot.patched
```

7. 解锁 Bootloader（见下方步骤）

8. 禁用 vbmeta 的验证, 刷入修补后的 boot 分区镜像文件到 boot 分区
```
python mtk.py da vbmeta 3
python mtk.py w boot boot.patched
```

9. 重启设备
```
python mtk.py reset
```

10. 断开 USB 的连接, 享受你的设备 :)


### 通过 payload 方式进入 fastboot 模式

例如:

```
python mtk.py payload --metamode FASTBOOT
```

### 提取 preloader 分区
```
mtk.py r preloader preloader.bin --parttype boot1
```

### 读取序列号/特殊分区
```
mtk.py r preloader preloader.bin --parttype boot2
```

### 读取 efuses

例如:

```
python mtk.py da efuse
```

### 解锁 bootloader

1. 擦除 metadata、userdata 和 md_udc 分区（注: 部分机型解锁 bootloader 之前需要擦除 userdata 用户数据, 当然你也可以选择不擦除）:
```
python mtk.py e metadata,userdata,md_udc
```

2. 解锁 Bootloader:
```
python mtk.py da seccfg unlock
```
重新上锁:
```
python mtk.py da seccfg lock
```

3. 重启设备:
```
python mtk.py reset
```

若 Android 11+ 出现 dm-verity 错误，按下电源键继续启动即可，设备会显示关于 bootloader 已解锁的黄色警告然后会在 5 秒内开机。


### 读取分区

通过 preloader 提取 boot 分区为 boot.bin 文件

```
python mtk.py r boot boot.bin
```

通过 bootrom 提取 boot 分区为 boot.bin 文件（其中 --preloader 为适用于你机型的 preloader 文件所在的路径）

```
python mtk.py r boot boot.bin [--preloader=Loader/Preloader/your_device_preloader.bin]
```


通过 bootrom 提取 preloader 分区为 preloader.bin 文件 (需使用 --preloader 来指定 preloader)

```
python mtk.py r preloader preloader.bin --parttype=boot1 [--preloader=Loader/Preloader/your_device_preloader.bin]
```

提取所有分区为 flash.bin 文件 (对于 BROM 模式请指定 --preloader)

```
python mtk.py rf flash.bin
```

提取所有分区为 flash.bin 文件 (对于 MT6261/MT2301 IoT 物联网设备) (对于 BROM 模式请指定 --preloader):

```
python mtk.py rf flash.bin --iot
```

提取 0x128000 偏移, 长度为 0x200000 的闪存为 flash.bin 文件 (对于 BROM 模式请指定 --preloader)

```
python mtk.py ro 0x128000 0x200000 flash.bin
```

提取所有分区到 "out" 文件夹 (对于 BROM 模式请指定 --preloader)

```
python mtk.py rl out
```

查看 gpt (对于 BROM 模式请指定 --preloader)

```
python mtk.py printgpt
```


将所有分区挂载为文件系统

```
python mtk.py fs /mnt/mtk
```

### 写入分区
(对于 BROM 模式请指定 --preloader)

写入 boot.bin 到 boot 分区

```
python mtk.py w boot boot.bin
```

刷入 flash.bin 以还原所有分区(仅在 DA 模式下可用)

```
python mtk.py wf flash.bin
```

刷入 "out" 文件夹中的所有分区文件

```
python mtk.py wl out
```

刷入在 flash.bin 中偏移 0x128000 长度为 0x200000 的闪存数据 (对于 BROM 模式请指定 --preloader)

```
python mtk.py wo 0x128000 0x200000 flash.bin
```

### 擦除分区

擦除 boot 分区
```
python mtk.py e boot
```

擦除 boot 分区的扇区
```
python mtk.py es boot [扇区数量]
```

### DA 命令:

读取内存
```
python mtk.py da peek [十六进制地址] [十六进制长度] [可选参数: -filename filename.bin 将读取的内容保存到名为 filename.bin 文件中]
```

写入内存
```
python mtk.py da poke [十六进制地址] [十六进制的字符串数据 或 -filename filename.bin 从 filename.bin 文件中写入数据]
```

读取 rpmb (只能在 xflash 中使用)
```
python mtk.py da rpmb r [will read to rpmb.bin]
```

写入 rpmb [只能在 xflash 中使用]
```
python mtk.py da rpmb w filename
```

生成并显示 rpmb1-3 密钥
```
python mtk.py da generatekeys
```

解锁 / 回锁 bootloader（lock=>回锁, unlock=>解锁）
```
python mtk.py da seccfg [lock 或 unlock]
```

---------------------------------------------------------------------------------------------------------------

### 绕过 SLA, DAA and SBC (通过 generic_patcher_payload)
`` 
python mtk.py payload
``  
如果你打算在待会使用 SP Flash Tool 工具，请确保你选择的是 "UART" 设置，而不是 "USB"。

### 提取 preloader
- 设备必须处于 bootrom 模式, 且 preloader 必须是完整的
```
python mtk.py dumppreloader [--ptype=["amonet","kamakiri","kamakiri2","hashimoto"]] [--filename=preloader.bin]
```

### 提取 brom
- 设备必须处于 bootrom 模式, 或者你可以通过让 DA 崩溃的方法然后进入 DA 模式
- 如果未指定任何选项，则将使用 Kamakiri 或 DA（DA 表示不安全目标）
- 如果将 "Kamakiri" 用作选项，则强制执行 Kamakiri
- 有效选项如下："kamakiri" （通过 usb_ctrl_handler 攻击）、"amonet"（通过 gcpu）和 "hashimoto"（通过 cqdma）

```
python mtk.py dumpbrom --ptype=["amonet","kamakiri","hashimoto"] [--filename=brom.bin]
```

要提取未知的 bootrom，请使用 brute 选项:
```
python mtk.py brute
```
如果成功提取，请在此处添加一个 Issue 并加上你的 bootrom 附件以添加完整的支持。

---------------------------------------------------------------------------------------------------------------

### 崩溃 da 以进入 brom

```
python mtk.py crash [--vid=vid] [--pid=pid] [--interface=interface]
```

### 使用修补过的 preloader 读取内存
- 在 Brom 中引导或崩溃到 Brom
```
python mtk.py peek [addr] [length] --preloader=patched_preloader.bin
```

### 运行自定义的 payload

```
python mtk.py payload --payload=payload.bin [--var1=var1] [--wdt=wdt] [--uartaddr=addr] [--da_addr=addr] [--brom_addr=addr]
```

---------------------------------------------------------------------------------------------------------------
## Stage2 用法
### 运行 python mtk.py stage (brom) 或者 mtk plstage (preloader)

#### 在 bootrom 模式下运行 stage2 
`` 
python mtk.py stage
`` 

#### 在 preloader 模式下运行 stage2 
`` 
python mtk.py plstage
`` 

#### 在 bootrom 模式下运行 stage2 plstage
- 在 Brom 中引导或崩溃到 Brom 模式
```
python mtk.py plstage --preloader=preloader.bin
```

### 使用 stage2 工具


### 退出 stage2 模式并重启
`` 
python stage2.py reboot
`` 

### 在 stage2 模式下读取 rpmb
`` 
python stage2.py rpmb
`` 

### 在 stage2 模式下读取 preloader
`` 
python stage2.py preloader
`` 

### 在 stage2 模式下将内存读取为十六进制数据
`` 
python stage2.py memread [开始地址] [数据长度]
`` 

### 在 stage2 模式下将内存读取到 filename.bin 文件
`` 
python stage2.py memread [开始地址] [数据长度] --filename filename.bin
`` 

### 在 stage2 模式下将十六进制的字符串数据写入内存
`` 
python stage2.py memwrite [开始地址] --data [十六进制的字符串数据]
`` 

### 在 stage2 模式下将文件中的数据写入内存
`` 
python stage2.py memwrite [开始地址] --filename filename.bin
`` 

### 提取密钥
`` 
python stage2.py keys --mode [sej, dxcc]
`` 
对于 dxcc，你需要使用 plstage 而不是 stage

---------------------------------------------------------------------

### 我遇到了个问题 ....... 请发送日志和完整的控制台详细信息！

- 使用 --debugmode 选项运行 mtk 工具。日志将写入 log.txt

## 配置 / 信息

### 芯片详细信息/配置
- 使用 config/brom_config.py
- 用于自动检测的未知 USB vid/pids 请使用 config/usb_ids.py
# [学习资源](https://github.com/bkerler/mtkclient/blob/main/learning_resources.md)
