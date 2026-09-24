# wireshark-protobuf-plugin (中文文档)

[English](README.md) | **中文**

这是一个 **Wireshark 协议解析插件（Dissector Plugin）**，支持在运行期动态解析自定义 TCP 承载的 [Protocol Buffers (protobuf)](https://protobuf.dev/) 消息，**无需预先代码生成（Code Generation）**。

本项目同时提供两种方案：
1. **Lua 脚本插件方案（推荐，零编译成本）**：单文件脚本 [`lua/packet-evil.lua`](file:///home/project/wireshark_protobuf_plugin/lua/packet-evil.lua)，免编译，支持跨平台（Windows / Linux / macOS），支持 `Ctrl+Shift+L` 热重载，直接转交 Wireshark 内置 Protobuf 解析器。
2. **C/C++ 二进制插件方案（高性能）**：基于 `evil/` + `libecho/`，利用 Google Protobuf 原生运行时反射，适合超大并发流量或需要私有加解密的场景。

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

1. **配置读取**：插件启动时读取 `config.xml`（或首选项），获取监听的 TCP **端口号**、对应的 `.proto` **协议文件名** 以及 **消息 ID（packet-id）到 Protobuf 消息类型名称（message-name）** 的映射规则。
2. **抓包解析**：
   - **Lua 方案**：解析 4 字节长度 + 2 字节 ID，自动处理 TCP 流分包与粘包重组，将剩余的二进制载荷挂载对应消息类型名称并移交 Wireshark 原生内置 Protobuf 解析引擎。
   - **C++ 方案**：利用 Google Protobuf 运行时反射机制（`Importer` + `DynamicMessageFactory`）进行动态反序列化，解出全部字段输出到树形节点。
3. **展示与过滤**：Wireshark 数据包详情中将各字段以树形展示，支持完整过滤语法。

---

## 目录结构

```
wireshark_protobuf_plugin/
├── lua/                    Lua 脚本解析器插件（推荐，免编译）
│   └── packet-evil.lua     单文件 Lua 解析器（支持 TCP 粘包重组与 Protobuf 转发）
├── evil/                   C 语言 Wireshark 插件动态库源码
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
│   └── ci.yml              GitHub Actions CI 流水线（单元测试 + C++ E2E + Lua E2E）
├── config.xml              运行时示例配置文件
├── README.md               英文主文档
└── README_zh.md            中文说明文档
```

---

## 方案一：Lua 插件（推荐）

### 安装步骤
将 [`lua/packet-evil.lua`](file:///home/project/wireshark_protobuf_plugin/lua/packet-evil.lua)、`config.xml` 以及您的 `.proto` 文件复制到 Wireshark 插件目录即可：
- **Linux 路径**：`~/.local/lib/wireshark/plugins/`
- **Windows 路径**：`%APPDATA%\Wireshark\plugins\`
- **macOS 路径**：`~/.config/wireshark/plugins/`

### 特性与优势
- **零编译**：跨平台直接可用，无需针对不同 Wireshark 版本折腾编译器和头文件。
- **热重载**：修改脚本或配置后，在 Wireshark 中按下 `Ctrl + Shift + L` 即可立即刷新。
- **TCP 流粘包/拆包重组**：内置 `desegment_offset` 与 `desegment_len` 处理机制。

---

## 方案二：C/C++ 二进制插件

### 环境依赖
- CMake 3.16+
- 支持 C++17 的编译器（GCC 9+ / Clang 10+ / MSVC 2019+）
- Protobuf 3.5+ (支持 3.x / 4.x / 21+)
- Wireshark 2.6 / 3.x / 4.x 开发头文件

### 步骤 1：编译辅助库 libecho
```bash
cd libecho
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### 步骤 2：编译 Wireshark 插件
**独立编译（Linux）：**
```bash
WS_VER=$(pkg-config --modversion wireshark | cut -d. -f1,2)
gcc -shared -fPIC -DPACKAGE="evil" -DVERSION="1.0.0" -DPLUGIN_VERSION="1.0.0" \
    -DVERSION_RELEASE="$WS_VER" -DHAVE_PLUGINS=1 $(pkg-config --cflags wireshark) \
    -Ievil -Ilibecho/libecho evil/packet-evil.c evil/plugin.c \
    libecho/build/libecho.a -lprotobuf -lstdc++ -o evil.so
```

**集成至 Wireshark 源码树编译：**
将 `evil/` 拷贝到 `<wireshark-src>/plugins/epan/evil`，在主 CMakeLists.txt 中注册后执行 `cmake --build build --target evil`。

---

## 配置文件说明 (`config.xml`)

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
    <!-- 如果 proto 包含 package（例如 package testpkg;），需填写全称：testpkg.LoginRequest -->
    <MsgId id="1001" name="testpkg.LoginRequest"/>
    <MsgId id="1002" name="testpkg.LoginResponse"/>
</Msg>
```

---

## Wireshark 过滤语法示例

- 按协议过滤：`myname`
- 按消息 ID 过滤：`myname.packetid == 1001`
- 按消息名称过滤：`myname.packetname == "testpkg.LoginRequest"`
- 检索 Protobuf 字段内容（C++ 插件）：`myname.body contains "alice"`

---

## 持续集成流水线 (CI)

仓库集成了 GitHub Actions 自动化流水线（[`.github/workflows/ci.yml`](file:///home/project/wireshark_protobuf_plugin/.github/workflows/ci.yml)），在每次提交时执行：
1. **`libecho` 跨平台单元测试**（Linux / Windows 矩阵通过 `CTest` 执行）。
2. **C++ 插件端到端验证**：编译 `evil.so` 并加载至 Wireshark/tshark，使用 Python 构造真实 TCP 数据包 pcap 进行解析过滤校验。
3. **Lua 插件端到端验证**：使用 `tshark -X lua_script:...` 直接加载 `packet-evil.lua`，并对生成的 pcap 报文进行端到端抓包校验。

---

## 开源协议

GPL-2.0-or-later（与 Wireshark 保持一致）。
