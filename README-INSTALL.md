## Install

### Linux - (Ubuntu recommended, no patched kernel needed except for kamakiri)

#### Install python >=3.10, git and other deps

#### Download source
```shell
sudo apt install git build-essential curl libssl-dev python3-pip -y
```

Use here github username for user and github token for password
```shell
git clone https://github.com/bkerler/mtkclient --recursive
```


#### For Debian/Ubuntu (here assuming fresh install)

#### Install pyenv
```shell
curl https://pyenv.run | bash
```
2. Follow the instructions and add
```shell
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```
to ~/.profile and ~/.bashrc
for example using nano ~/.profile, paste at the end, then ctrl-o, enter, ctrl-x

3. Add this line eval "$(pyenv virtualenv-init -)" to the end of ~/.bashrc
```shell
sudo apt install libbz2-dev liblz4-dev liblzma-dev python3-tk tk-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev -y
sudo cp mtkclient/Setup/Linux/*.rules /etc/udev/rules.d/
sudo udevadm control -R && sudo udevadm trigger && cd ..
sudo usermod -aG dialout $USER && sudo usermod -aG plugdev $USER
```
Reboot the PC, then :
```shell
pyenv install 3.13
pyenv global 3.13
```

#### Setup additional requirements
```shell
sudo apt install google-android-platform-tools-installer
sudo apt install libfuse-dev
sudo apt install libxcb-cursor0
```

#### Setup requirements using pip
Open up a new terminal
```shell
cd mtkclient && pip3 install -r requirements.txt
```

#### Setup requirements using [uv](https://docs.astral.sh/uv/)
Open up a new terminal
```shell
cd mtkclient && uv sync --frozen
```

#### For ArchLinux
```shell
(sudo) pacman -S  python python-pip python-pipenv git libusb fuse2
```
or
```shell
yay -S python python-pip git libusb fuse2
```

#### For Fedora
```shell
sudo dnf install python3 git libusb1 fuse
sudo groupadd plugdev
```

### Using venv
```shell
python3 -m venv ~/.venv
git clone https://github.com/bkerler/mtkclient
cd mtkclient
. ~/.venv/bin/activate
pip install -r requirements.txt
pip install .
```

#### Install rules
```shell
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER
sudo cp Setup/Linux/*.rules /etc/udev/rules.d
sudo udevadm control -R
sudo udevadm trigger
```
Make sure to reboot after adding the user to dialout/plugdev. If the device
has a vendor interface 0xFF (like LG), make sure to add "blacklist qcaux" to
the "/etc/modprobe.d/blacklist.conf".

---------------------------------------------------------------------------------------------------------------

### macOS

#### Install brew, macFUSE, OpenSSL

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install macfuse openssl
```

You may need to **reboot**

#### Grab files
```shell
git clone https://github.com/bkerler/mtkclient
cd mtkclient
```

#### Create python 3.9 venv and install dependencies
```shell
python3.9 -m venv mtk_venv
source mtk_venv/bin/activate
pip3 install --pre --no-binary capstone capstone
pip3 install PySide6 libusb
pip3 install -r requirements.txt
```

---------------------------------------------------------------------------------------------------------------
### Use kamakiri (optional, only needed for mt6260 or older)

- For linux (kamakiri attack), you need to recompile your linux kernel using this kernel patch :
```shell
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev libdw-dev
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
cd pahole && mkdir build && cd build && cmake .. && make && sudo make install
sudo mv /usr/local/libdwarves* /usr/local/lib/ && sudo ldconfig
```

```shell
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-`uname -r`.tar.xz
tar xvf linux-`uname -r`.tar.xz
cd linux-`uname -r`
patch -p1 < ../../mtkclient/Setup/kernelpatches/disable-usb-checks-5.10.patch
cp -v /boot/config-$(uname -r) .config
make menuconfig
make
sudo make modules_install
sudo make install
```

- These aren't needed for current ubuntu (as make install will do, just for reference):

```shell
sudo update-initramfs -c -k `uname -r`
sudo update-grub
```

See Setup/kernels for ready-to-use kernel setups


- Reboot

```shell
sudo reboot
```
