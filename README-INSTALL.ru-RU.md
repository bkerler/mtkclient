## Установка

### Linux — (рекомендуется Ubuntu, пропатченное ядро не нужно, кроме kamakiri)

#### Установка python >=3.10, git и других зависимостей

#### Скачивание исходников
```shell
sudo apt install git build-essential curl libssl-dev python3-pip -y
```

Здесь в качестве user указывается имя пользователя GitHub, в качестве password — токен GitHub
```shell
git clone https://github.com/bkerler/mtkclient --recursive
```


#### Для Debian/Ubuntu (здесь предполагается свежая установка)

#### Установка pyenv
```shell
curl https://pyenv.run | bash
```
2. Следуйте инструкциям и добавьте
```shell
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```
в ~/.profile и ~/.bashrc
например, через nano ~/.profile: вставьте в конец файла, затем ctrl-o, enter, ctrl-x

3. Добавьте строку eval "$(pyenv virtualenv-init -)" в конец ~/.bashrc
```shell
sudo apt install libbz2-dev liblz4-dev liblzma-dev python3-tk tk-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev -y
sudo cp mtkclient/Setup/Linux/*.rules /etc/udev/rules.d/
sudo udevadm control -R && sudo udevadm trigger && cd ..
sudo usermod -aG dialout $USER && sudo usermod -aG plugdev $USER
```
Перезагрузите ПК, затем:
```shell
pyenv install 3.13
pyenv global 3.13
```

#### Установка дополнительных зависимостей
```shell
sudo apt install google-android-platform-tools-installer
sudo apt install libfuse-dev
sudo apt install libxcb-cursor0
```

#### Установка зависимостей через pip
Откройте новый терминал
```shell
cd mtkclient && pip3 install -r requirements.txt
```

#### Установка зависимостей через [uv](https://docs.astral.sh/uv/)
Откройте новый терминал
```shell
cd mtkclient && uv sync --frozen
```

#### Для ArchLinux
```shell
(sudo) pacman -S  python python-pip python-pipenv git libusb fuse2
```
или
```shell
yay -S python python-pip git libusb fuse2
```

#### Для Fedora
```shell
sudo dnf install python3 git libusb1 fuse-libs
sudo cp Setup/Linux/52-mtk.rules /etc/udev/rules.d/52-mtk.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### Использование venv
```shell
python3 -m venv ~/.venv
git clone https://github.com/bkerler/mtkclient
cd mtkclient
. ~/.venv/bin/activate
pip install -r requirements.txt
pip install .
```

#### Установка правил udev
```shell
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER
sudo cp Setup/Linux/*.rules /etc/udev/rules.d
sudo udevadm control -R
sudo udevadm trigger
```
После добавления пользователя в dialout/plugdev обязательно перезагрузитесь. Если у устройства
есть вендорский интерфейс 0xFF (как у LG), добавьте "blacklist qcaux" в
"/etc/modprobe.d/blacklist.conf".

---------------------------------------------------------------------------------------------------------------

### macOS

#### Установка brew, macFUSE, OpenSSL

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install macfuse openssl
```

Может потребоваться **перезагрузка**

#### Скачивание файлов
```shell
git clone https://github.com/bkerler/mtkclient
cd mtkclient
```

#### Создание venv с python 3.9 и установка зависимостей
```shell
python3.9 -m venv mtk_venv
source mtk_venv/bin/activate
pip3 install --pre --no-binary capstone capstone
pip3 install PySide6 libusb
pip3 install -r requirements.txt
```

#### Примечания для macOS Apple Silicon (M1/M2/M3)

На Mac с Apple Silicon помимо общих инструкций для macOS выше нужно сделать несколько дополнительных шагов:

1. **Установите Python из Homebrew (3.10 или новее) вместо системного Python.**
   Системный Python на Apple Silicon часто устаревший и может не собрать нативные
   зависимости. Используйте версию из Homebrew:
   ```shell
   brew install python@3.10
   python3.10 -m venv mtk_venv
   source mtk_venv/bin/activate
   ```

2. **Соберите capstone из исходников.** Готовых arm64-колёс для зафиксированной версии
   capstone нет, поэтому флаг `--no-binary` обязателен:
   ```shell
   pip3 install --pre --no-binary capstone capstone
   ```

3. **Установите libusb через Homebrew.** Он ставится как keg-only, поэтому убедитесь,
   что загрузчик сможет его найти, если колёса с зависимостью от libusb его не обнаружат:
   ```shell
   brew install libusb
   export DYLD_LIBRARY_PATH="$(brew --prefix libusb)/lib:$DYLD_LIBRARY_PATH"
   ```

4. **Одобрите системное расширение macFUSE.** На Apple Silicon расширения ядра
   требуют одобрения пользователем и режима пониженной безопасности:
   - После выполнения `brew install macfuse` откройте **Системные настройки → Конфиденциальность и безопасность**
     и нажмите **Разрешить** для заблокированного системного ПО от Benjamin Fleischer.
   - Если расширение всё ещё заблокировано, загрузитесь в **Режим восстановления**, выберите
     **Утилиты → Утилита безопасности загрузки → Пониженная безопасность** и включите
     **«Разрешить управление расширениями ядра от идентифицированных разработчиков»**.
   - После одобрения **перезагрузитесь**.

5. **GUI (mtk_gui) на arm64.** PySide6 поставляется с универсальными колёсами universal2/arm64,
   поэтому GUI работает на Apple Silicon, но если он не запускается, убедитесь, что venv создан
   из Python из Homebrew (arm64), а не из x86_64-версии Python под Rosetta:
   ```shell
   file -L "$(command -v python3)"   # должно быть arm64
   ```

---------------------------------------------------------------------------------------------------------------
### Использование kamakiri (опционально, нужно только для mt6260 или старше)

- Для linux (атака kamakiri) нужно пересобрать ядро linux с этим патчем ядра:
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

- Для актуальной Ubuntu это не нужно (make install делает это сам; здесь просто для справки):

```shell
sudo update-initramfs -c -k `uname -r`
sudo update-grub
```

Готовые конфигурации ядра смотрите в Setup/kernels


- Перезагрузка

```shell
sudo reboot
```
