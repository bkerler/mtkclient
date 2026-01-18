## 安装步骤

### Linux - (推荐使用 Ubuntu, 除了 Kamakiri 内核外，无需其他修补过补丁的内核)

#### 安装 python >=3.8、git 和其他依赖项

#### Debian/Ubuntu
```
sudo apt install python3 git libusb-1.0-0 python3-pip libfuse2
```
#### ArchLinux
```
sudo pacman -S  python python-pip python-pipenv git libusb fuse2
```
或者
```
yay -S python python-pip git libusb fuse2
```

#### Fedora
```
sudo dnf install python3 git libusb1 fuse
```

#### 获取文件
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
pip3 install -r requirements.txt
pip3 install .
```

### 使用 venv
```
python3 -m venv ~/.venv
git clone https://github.com/bkerler/mtkclient
cd mtkclient
. ~/.venv/bin/activate
pip install -r requirements.txt
pip install .
```

#### 安装规则
```
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER
sudo cp mtkclient/Setup/Linux/*.rules /etc/udev/rules.d
sudo udevadm control -R
sudo udevadm trigger
```
将用户添加到 dialout/plugdev 后，请务必重启系统。如果设备有厂商接口 0xFF (例如 LG)，需添加 ``blacklist qcaux`` 到配置文件 ``/etc/modprobe.d/blacklist.conf``。

---------------------------------------------------------------------------------------------------------------

### macOS

#### 安装 brew, macFUSE, OpenSSL

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install macfuse openssl
```

安装完后可能需要 **重启**

#### 获取文件
```
git clone https://github.com/bkerler/mtkclient
cd mtkclient
```

#### 创建 python 3.9 venv 虚拟环境并安装依赖
```
python3.9 -m venv mtk_venv
source mtk_venv/bin/activate
pip3 install --pre --no-binary capstone capstone
pip3 install PySide6 libusb
pip3 install -r requirements.txt
```

---------------------------------------------------------------------------------------------------------------
### 使用 kamakiri (可选，仅适用于 mt6260 或更早的处理器)

- 对于 linux (kamakiri 内核), 你需要使用此内核补丁来重新编译 Linux 内核:
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

- 注: 这些对于当前的 Ubuntu 系统来说并不需要 (因为 make install 就可以完成，仅供参考)：

```
sudo update-initramfs -c -k `uname -r`
sudo update-grub
```

你可以在 ``Setup/kernels`` 目录中获取开箱即用的内核配置。


- 重启

```
sudo reboot
```
