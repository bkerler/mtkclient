<div align="right">
  Language:
  <a title="English" href="./README.md">🇺🇸</a>
  🇨🇳
</div>

# MTKClient
![Logo](mtkclient/gui/images/logo_256.png)

这是一款用于联发科芯片的调试工具，支持读写分区、利用漏洞对设备进行底层操作。
在Windows系统下使用需要安装MTK串口驱动和UsbDk驱动 (详见下方说明)。
在Linux系统下，如果你使用的是旧版的kamakiri内核则需要使用内核补丁 (参见Setup目录)，但读写分区等操作则不需要补丁。

打开 MTKClient, 在设备完全关机的情况下按住音量上键+电源键或音量下键+电源键进入Brom模式，待工具检测到设备后松手。

## MT6781, MT6789, MT6855, MT6886, MT6895, MT6983, MT8985
- 这些联发科处理器用的是 V6 协议且 Bootrom 漏洞已被修复，需使用 ``--loader`` 指定有效的 DA 文件。
- 在部分设备上，预引导程序 preloader 被禁用了，但是你仍可以通过执行 ``adb reboot edl`` 来使用它。
- 当前仅支持未熔断的设备 (UNFUSED)。
- 对于所有已启用 DAA、SLA 和远程验证 的设备，目前尚无公开解决方案 (原因多种多样)。

## 致谢
- kamakiri [xyzz]
- linecode exploit [chimera]
- Chaosmaster
- Geert-Jan Kreileman (GUI 设计及优化)
- 所有贡献者

## 安装

### 使用 Re LiveDVD (基于 Ubuntu, 开箱即用):
用户: user, 密码: user (基于 Ubuntu 22.04 LTS)

[Live DVD V6](https://www.androidfilehost.com/?fid=1109791587270922802)


## 安装步骤
[Linux](README-INSTALL.zh-CN.md)
[Windows](README-WINDOWS.zh-CN.md)

## 使用方法
[使用方法](README-USAGE.zh-CN.md)

### 我遇到了个问题 ....... 请发送日志和完整的控制台详细信息！

- 使用 --debugmode 选项运行 mtk 工具。日志将写入 log.txt

## 配置 / 信息

### 芯片详细信息/配置
- 转到 config/brom_config.py
- 如果 USB VID/PID 未知，请使用 `config/usb_ids.py` 进行自动检测。
# [学习资源](https://github.com/bkerler/mtkclient/blob/main/learning_resources.md)
