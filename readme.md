# wireshark的protobuf协议的插件 #
* 首先打开libecho工程，修改config.xml文件，改成对应的协议，编译成libecho.lib
* 下载wireshark 2.2的src包
* 复制evil工程到plugin目录下，修改总CMake文件加入evil工程
* 用CMake生成vs2015的工程
* 打开libecho工程，修改config.xml文件，改成对应的协议
* 打开工程，修改对应各自的解包代码，修改显示的协议名字和字段
* 编译evil对应的工程，输出evil.dll
* 把evil.dll文件拷贝到wireshark安装目录的plugin下，把config.xml和proto配置文件拷贝到wireshark安装目录
* 重启wireshark，在筛选中输入协议名字即可
