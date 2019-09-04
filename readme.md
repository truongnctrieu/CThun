# CThon(克苏恩)
CThon是集成快速端口扫描服务识别和暴力破解的工具.
# 优点
* 扫描速度快(255个IP,TOP100端口,15秒)
* 服务识别准确(集成NMAP指纹数据库)
* 单文件无依赖(方便内网扫描)
* 适应性强(Windows Server 2003 -- Windows Server 2012)
* 支持多种协议暴力破解
# 缺点
* 可执行文件大(20M)
# 使用方法
* 将可执行文件chton.exe上传到已控制主机
* chton -h 查看帮助信息
## 命令样例
```
cthon.exe -s 192.168.3.10 -e 192.168.3.100 --topports 100 --bf 1 --no_default_dict 1
```
扫描192.168.3.1的C段的top100端口和33899,33999端口,端口扫描完成后进行密码暴力破解,不使用内置的字典,结果会保存到result.log文件中
# 已测试
* Windows Server 2012
* Windows Server 2003
* Windows7
* CentOS6
# 工具截图
![图片](https://uploader.shimo.im/f/b6C7NjlGM44D8kJ1.png!thumbnail)
![图片](https://uploader.shimo.im/f/wGv9M6IRjjgCO4j4.png!thumbnail)

克苏恩是魔兽世界电子游戏中一位上古之神,全身都是眼睛.
