# CThun
CThun是集成快速端口扫描,服务识别,网站识别和暴力破解的工具.
# 优点
* 端口扫描扫描速度快(255个IP,TOP100端口,15秒)
* 服务识别准确(集成NMAP指纹数据库)
* 单文件无依赖(方便内网扫描)
* 适应性强(Windows Server 2003,Windows Server 2012,CentOS6,Debain9,ubuntu16)
* 支持多种协议暴力破解
# 缺点
* 可执行文件大(20M)
# 依赖
* Postgresql及RDP的暴力破解依赖OpenSSL(Windows Server 2003/Windows XP不能使用这两个暴力破解功能,其他功能无影响)
* Linux服务器需要glibc版本大于2.12(ldd --version查看)
# 使用方法
* 将可执行文件chton.exe上传到已控制主机
* chtun -h 查看帮助信息
## 命令样例
```
cthun.exe -s 192.168.3.10 -e 192.168.3.100 -tp 100 -p 33899-33901
```
扫描192.168.3.1的C段的top100端口和33899,33900,33901端口,结果会保存到result.log文件中

```
cthun.exe -s 192.168.3.10 -e 192.168.3.100 -tp 100 -p 33899-33901 -hs
```
端口扫描完成后针对http(s)服务进行增强扫描

```
cthun.exe -s 192.168.3.10 -e 192.168.3.100 -tp 100 -p 33899-33901 -bf smb,rdp -nd
```
端口扫描完成后针对smb和rdp服务进行暴力破解,不使用内置字典只使用自定义字典

```
cthun.exe -s 192.168.3.10 -e 192.168.3.100 -tp 100 -p 33899-33901 -bf all 
```
端口扫描完成后针对ftp, ssh, rdp, smb, mysql, mssql, redis, mongodb, memcached,postgresql, vnc服务进行暴力破解,使用内置字典和自定义字典
# 已测试
* Windows server 2003
* Windows7
* Windows Server 2012
* CentOS6
* Kali
# 工具截图
![图片](https://uploader.shimo.im/f/jxgOCMlyvbMEnsig.png!thumbnail)
![图片](https://uploader.shimo.im/f/djUIDtYzRI8gh2a8.png!thumbnail)

# 更新日志
**1.0 beta**
更新时间: 2019-09-04
* 增加暴力破解功能

**1.1**
更新时间: 2019-09-11
* 修复windows server 2003 无法打开问题
* linux依赖降低到glibc2.12版本
* 端口扫描支持输入范围(1-65535全端口)
* 暴力破解模块支持指定需要破解的协议
* 更快捷的命令行参数
* 新增http(s)服务增强扫描,获取title,status_code,网站组件等信息
* 端口扫描输出格式更加友好

cthun(克苏恩)是魔兽世界电子游戏中一位上古之神
