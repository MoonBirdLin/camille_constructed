# Camille_construced

- 修改自 [camille](https://github.com/zhengjim/camille)
- 借用了 camille 的代码架构, 修改了部分代码, 使得这份工具更加适用于进行逆向分析的初步 Hook 过程。

## 简介

经作者测试 camille 的代码结构非常适合学习、理解、调试和修改。出于逆向学习以及 Android App 漏洞挖掘的常规需求，新增了返回值打印、对象 field 打印等功能，便于在逆向过程中快速定位变量。

TODOs: 

- [x] 提供 json 格式输出（xls存在每个单元格 32767 个字符的限制, 直接在excel.xls输出的目录创建一个json文件用于记录）
- [ ] 支持 python 命令行/Config 文件输入 API 列表后自动填充进加载的 JS 脚本中，减少修改 Hook 目标时的额外精力
- [ ] 增加可配置 Hook 函数并修改参数/返回值的功能

p.s. 本项目根据工作需求程度随缘更新，望见谅。

## 安装

环境：

python3、frida 、一台已root手机(我测试机为Oppo OnePlus ，使用ColorOS 13)，并在手机上运行`frida-server`（也可以使用各种反对抗版本的Frida，例如[Florida](https://github.com/Ylarod/Florida)）。

p.s. 
- Android 和 Frida 多出玄学 bug，很难远程解决
- 潜在解决方案包括但不限于更换测试机、更换系统版本、更换 frida 版本、调整 frida-server 启动时机（参考 [MagiskFrida](https://github.com/AeonLucid/MagiskFrida)）、调整 frida 启动时延（本工具的 `-t` 参数），各种 xposed/magisk 过检测模块的启用、使用 frida-gadget （直接注入或者[ZygiskFrida](https://github.com/lico-n/ZygiskFrida)）、调整系统属性（参考 [magisk-frida](https://github.com/MoonBirdLin/magisk-frida)）等

更新日志：

```
2024-09-08 及之前：修改代码支持返回值打印、有限深度对象 field 序列化打印、删除隐私政策相关处理过程以及文档、更新Readme。
```

使用：

```
git clone https://github.com/MoonBirdLin/camille_constructed
cd camille_constructed
pip install -r requirements.txt
cp script_origin.js script.js
python camille.py -h
```

![img.png](images/img.png)

## 用法

[使用说明文档](docs/use.md)

## 参考链接

- https://github.com/zhengjim/camille
- https://github.com/Dawnnnnnn/APPPrivacyDetect
- https://github.com/r0ysue/r0capture/
- https://github.com/ChenJunsen/Hegui3.0
