<div align="right">
  Language:
  🇺🇸
  <a title="Chinese" href="./README.zh-CN.md">🇨🇳</a>
</div>

# MTKClient
![Logo](mtkclient/gui/images/logo_256.png)

Just some mtk tool for exploitation, reading/writing flash and doing crazy stuff. 
For windows, you need to install the stock mtk port and the usbdk driver (see instructions below).
For linux, a patched kernel is only needed when using old kamakiri (see Setup folder) (except for read/write flash).

Once the mtk script is running, boot into brom mode by powering off device, press and hold either
vol up + power or vol down + power and connect the phone. Once detected by the tool,
release the buttons.

## MT6781, MT6789, MT6855, MT6886, MT6895, MT6983, MT8985
- These chipsets use a new protocol called V6 and the bootrom is patched. 
You need to use the --loader option and a proper loader from the Loaders/V6 directory. 
Bootrom won't work, you need to use preloader mode (no hw buttons pressed, just connect). 
On some devices, preloader is deactivated, but you can reactivate it by running "adb reboot edl".

## Credits
- kamakiri [xyzz]
- linecode exploit [chimera]
- Chaosmaster
- Geert-Jan Kreileman (GUI, design & fixes)
- All contributors

### Installation

[See linux/macos installation hints](README-INSTALL.md)

[See windows installation hints](README-WINDOWS.md)

### Usage
[See usage instructions](README-USAGE.md)

### Use Re LiveDVD (everything ready to go, based on Ubuntu):
User: user, Password:user (based on Ubuntu 22.04 LTS)

[Live DVD V6](https://www.androidfilehost.com/?fid=1109791587270922802)

### I have issues ....... please send logs and full console details !

- Run the mtk tool with --debugmode. Log will be written to log.txt (hopefully)

## Rules / Infos

### Chip details / configs
- Go to config/brom_config.py
- Unknown usb vid/pids for autodetection go to config/usb_ids.py

## Other Stuff 
[Learning resources](learning_resources.md)
