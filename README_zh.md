# wireshark-protobuf-plugin (中文文档)

[English](README.md) | **中文**

这是一个 **Wireshark 协议解析插件（Dissector Plugin）**，支持在运行期动态解析自定义 TCP 承载的 [Protocol Buffers (protobuf)](https://protobuf.dev/) 消息，**无需预先代码生成（Code Generation）**。

兼容 **Wireshark 2.6 / 3.x / 4.x**（支持 Linux 与 Windows）。

---

## 协议包格式与工作原理

```
TCP 应用层数据包结构：
  ┌─────────────────────────────────────────────────┐
  │ 4 bytes │  2 bytes  │  N bytes                  │
  │ datasize│ packet-id │  protobuf body (N = datasize-2) │
  └─────────────────────────────────────────────────┘
```

1. 插件启动时读取 `config.xml`，获取目标 TCP **端口号**、对应的 `.proto` **协议文件名** 以及 **消息 ID（packet-id）到 Protobuf 消息类型名称（message-name）** 的映射规则。
2. 捕获报文时，插件借助 Google Protobuf 的运行时反射与动态导入机制（`google::protobuf::compiler::Importer` 与 `DynamicMessageFactory`），实时载入 `.proto` 文件并进行反序列化，无需执行 `protoc` 生成 C++ 代码。
3. 将解包出的字段作为树形子节点展示在 Wireshark 界面中，并支持按字段进行过滤筛选。

---

## 目录结构

```
wireshark_protobuf_plugin/
├── evil/                   Wireshark 解析器插件源码 (C)
│   ├── packet-evil.c       核心解析逻辑（Dissector 实现）
│   ├── plugin.c            Wireshark 插件动态加载入口
│   ├── packet-evil.h
│   ├── moduleinfo.h
│   └── CMakeLists.txt      Wireshark 源码树内构建规则
├── libecho/                C++ 底层动态解析与配置加载辅助库
│   ├── CMakeLists.txt      独立 CMake 构建配置（带 CTest 单测）
│   ├── libecho/
│   │   ├── libecho.h       对外导出的 C 接口
│   │   ├── libecho.cpp     Protobuf 动态反射与 XML 配置解析实现
│   │   ├── config.h        XML 配置结构体定义
│   │   ├── tinyxml.*       内置 TinyXML 解析库
│   │   └── tinystr.*
│   └── test/
│       ├── test.cpp        单元测试用例
│       ├── test.proto      测试协议
│       └── config.xml      测试配置
├── .github/workflows/
│   └── ci.yml              GitHub Actions CI 流水线（Linux/Windows 单元测试与端到端测试）
├── config.xml              运行时示例配置文件
├── README.md               英文主文档
└── README_zh.md            中文说明文档
```

---

## 编译指南

### 环境依赖

| 依赖组件 | 最低版本要求 |
|---------|-------------|
| CMake | 3.16+ |
| C 编译器 | GCC 9+ / Clang 10+ / MSVC 2019+ |
| C++ 编译器 | 支持 C++17 的编译器 |
| Protobuf | 3.5+ (支持 3.x / 4.x / 21+) |
| Wireshark 开发包 | Wireshark 2.6 / 3.x / 4.x 开发头文件 |

### 步骤 1：编译辅助库 libecho

```bash
cd libecho
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build

# 运行单元测试
ctest --test-dir build --output-on-failure
```
编译产物位于 `build/libecho.a`（Linux）或 `build/libecho.lib`（Windows）。

---

### 步骤 2：编译 Wireshark 插件

#### 方式 A：独立编译（针对已安装 Wireshark 的开发环境）
以 Linux 为例：
```bash
# 获取本机安装的 Wireshark 版本分支（如 2.6、3.6、4.2 等）
WS_VER=$(pkg-config --modversion wireshark | cut -d. -f1,2)

gcc -shared -fPIC -DPACKAGE="evil" -DVERSION="1.0.0" -DPLUGIN_VERSION="1.0.0" \
    -DVERSION_RELEASE="$WS_VER" -DHAVE_PLUGINS=1 $(pkg-config --cflags wireshark) \
    -Ievil -Ilibecho/libecho evil/packet-evil.c evil/plugin.c \
    libecho/build/libecho.a -lprotobuf -lstdc++ -o evil.so
```

#### 方式 B：集成至 Wireshark 源码树编译
1. 下载与您安装的 Wireshark 大版本匹配的源码。
2. 将 `evil` 目录拷贝到 Wireshark 源码目录下的 `plugins/epan/evil`。
3. 修改 Wireshark 的主 `CMakeLists.txt`，在插件列表变量中追加 `plugins/epan/evil`。
4. 运行 CMake 构建：
```bash
cd <wireshark-source>
cmake -S . -B build -DENABLE_PLUGINS=ON
cmake --build build --target evil
```

---

## 插件安装与配置

将编译生成的插件文件及配置放置于 Wireshark 的插件目录：
- Linux 路径：`~/.local/lib/wireshark/plugins/<版本号>/epan/`
- Windows 路径：`%APPDATA%\Wireshark\plugins\<版本号>\epan\`

需要放置的文件：
1. `evil.so`（Linux）或 `evil.dll`（Windows）
2. `config.xml`（协议配置及映射规则）
3. 对应的 `.proto` 文件（放于启动目录或 Wireshark 插件目录）

### config.xml 结构示例

```xml
<Msg>
    <!-- port: 监听的目标 TCP 端口；proto: 关联的 proto 协议定义文件名 -->
    <Config port="12345"
            proto="GameProtos.proto"
            clientregid="1"
            serverregid="101"
            regkey="aaa"
            key="bbb"/>

    <!-- 消息 ID 映射到 proto 中定义的 Message 名称 -->
    <!-- 如果 proto 包含 package（例如 package mygame;），需填写全称：mygame.LoginRequest -->
    <MsgId id="1001" name="mygame.LoginRequest"/>
    <MsgId id="1002" name="mygame.LoginResponse"/>
</Msg>
```

---

## Wireshark 抓包与过滤

重启 Wireshark（或运行 `tshark`）后，插件将自动激活。

在顶部显示过滤器输入过滤表达式：
- 按协议过滤：`myname`
- 按消息 ID 过滤：`myname.packetid == 1001`
- 按消息名称过滤：`myname.packetname == "mygame.LoginRequest"`
- 检索 Protobuf 字段内容：`myname.body contains "alice"`

---

## 常见问题排查

| 现象 | 排查方案 |
|------|---------|
| 插件未加载 | 打开 Wireshark 菜单 `帮助(Help) -> 关于(About Wireshark) -> 插件(Plugins)`，查看是否存在 `evil.so` / `evil.dll`。检查插件存放路径中的版本目录是否与 Wireshark 版本精确匹配（如 4.x 需位于 `epan/` 子目录）。 |
| 报文中显示 `(not initialized)` | 未能在当前工作目录或插件目录找到 `config.xml` 或配置中声明的 `.proto` 文件。 |
| 报文中显示 `(unknown message id)` | 收到的消息包 ID 未在 `config.xml` 的 `<MsgId>` 列表中配置。 |
| 报文中显示 `(ParseFromArray failed)` | 二进制数据不匹配该 Protobuf 消息结构，请核对包头偏移量（4字节长度 + 2字节ID）或字节序。 |
| 加载时 Wireshark 崩溃或报 ABI 错误 | Wireshark 插件 ABI 对版本非常严格，必须使用与目标 Wireshark 相同大版本及编译环境重新编译插件。 |

---

## 开源协议

GPL-2.0-or-later（与 Wireshark 保持一致）。
