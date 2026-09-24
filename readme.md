# wireshark-protobuf-plugin

**English** | [中文](README_zh.md)

A **Wireshark dissector plugin** that decodes custom TCP streams carrying
[Protocol Buffers (protobuf)](https://protobuf.dev/) messages at runtime –
no code generation required.

Two implementations are provided:
1. **Lua Plugin (`lua/packet-evil.lua`)**: Lightweight, cross-platform (Windows/Linux/macOS), zero compilation required, supports hot-reloading (`Ctrl+Shift+L`). Recommended for most users.
2. **C/C++ Binary Plugin (`evil/` + `libecho/`)**: High performance, native Protobuf dynamic reflection, ideal for heavy traffic or custom packet processing.

Supports **Wireshark 2.6 / 3.x / 4.x** on Linux and Windows.

---

## How it works

```
TCP packet
  ┌─────────────────────────────────────────────────┐
  │ 4 bytes │  2 bytes  │  N bytes                  │
  │ datasize│ packet-id │  protobuf body (N = datasize-2) │
  └─────────────────────────────────────────────────┘
```

1. The plugin reads `config.xml` (or preference settings) to obtain the TCP **port**, the `.proto` filename, and the **packet-id → message-name** mapping.
2. At capture time:
   - **Lua plugin**: Parses the 6-byte header and passes the remaining Protobuf payload to Wireshark's built-in Protobuf dissector with the corresponding message name.
   - **C++ plugin**: Dynamically parses `.proto` using Google Protobuf reflection (`Importer` + `DynamicMessageFactory`) and deserializes every field into the tree.
3. Every field is rendered hierarchically in the Wireshark packet tree and is fully filterable.

---

## Repository layout

```
wireshark_protobuf_plugin/
├── lua/                    Lua dissector plugin (Zero compilation)
│   └── packet-evil.lua     Single-file Lua dissector with TCP desegmentation
├── evil/                   Wireshark dissector plugin (C binary)
│   ├── packet-evil.c       Dissector – main dissection logic
│   ├── plugin.c            Wireshark plugin entry points
│   ├── packet-evil.h
│   ├── moduleinfo.h
│   └── CMakeLists.txt      (integrated into Wireshark source tree)
├── libecho/                C++ helper library for C plugin
│   ├── CMakeLists.txt      (standalone build with CTest)
│   ├── libecho/
│   │   ├── libecho.h       C API exposed to the dissector
│   │   ├── libecho.cpp     Protobuf reflection + XML config loader
│   │   ├── config.h        XML config class
│   │   ├── tinyxml.*       Embedded TinyXML parser
│   │   └── tinystr.*
│   └── test/
│       ├── test.cpp        libecho unit tests
│       ├── test.proto      Test proto definition
│       └── config.xml      Test XML configuration
├── .github/workflows/
│   └── ci.yml              GitHub Actions CI (Unit tests + C++ E2E + Lua E2E)
├── config.xml              Runtime config (copy to Wireshark plugin dir)
├── README.md               Main documentation (English)
└── README_zh.md            Secondary documentation (Chinese)
```

---

## Solution 1: Lua Plugin (Recommended)

### Installation
Copy [`lua/packet-evil.lua`](file:///home/project/wireshark_protobuf_plugin/lua/packet-evil.lua), `config.xml`, and your `.proto` file to your Wireshark Personal Plugins directory:
- **Linux**: `~/.local/lib/wireshark/plugins/`
- **Windows**: `%APPDATA%\Wireshark\plugins\`
- **macOS**: `~/.config/wireshark/plugins/`

### Features
- **Zero compilation**: Works immediately without building `.so` or `.dll`.
- **Hot reload**: Press `Ctrl + Shift + L` in Wireshark to reload scripts after edits.
- **TCP Stream Reassembly**: Automatically handles TCP segmentation and fragment reassembly.

---

## Solution 2: C/C++ Binary Plugin

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| CMake | 3.16 |
| C/C++ compiler | GCC 9 / Clang 10 / MSVC 2019 (C++17) |
| Wireshark dev headers | 2.6 / 3.x / 4.x |
| Protobuf | 3.5+ (3.x / 4.x / 21+) |

### Step 1 – build libecho

```bash
cd libecho
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### Step 2 – build evil plugin

**Standalone compilation (Linux):**
```bash
WS_VER=$(pkg-config --modversion wireshark | cut -d. -f1,2)
gcc -shared -fPIC -DPACKAGE="evil" -DVERSION="1.0.0" -DPLUGIN_VERSION="1.0.0" \
    -DVERSION_RELEASE="$WS_VER" -DHAVE_PLUGINS=1 $(pkg-config --cflags wireshark) \
    -Ievil -Ilibecho/libecho evil/packet-evil.c evil/plugin.c \
    libecho/build/libecho.a -lprotobuf -lstdc++ -o evil.so
```

**Or integrate into Wireshark source tree:**
Copy `evil/` to `<wireshark-src>/plugins/epan/evil`, add to `PLUGIN_SRC_DIRS` in Wireshark's root `CMakeLists.txt`, and build with `cmake --build build --target evil`.

---

## Configuration (`config.xml`)

```xml
<Msg>
  <Config port="12345"
          proto="GameProtos.proto"
          clientregid="1"
          serverregid="101"
          regkey="aaa"
          key="bbb"/>

  <!-- Map numeric packet-ids to proto message names -->
  <MsgId id="1001" name="testpkg.LoginRequest"/>
  <MsgId id="1002" name="testpkg.LoginResponse"/>
</Msg>
```

> **Note:** If your message is in a protobuf package (e.g. `package testpkg;`), provide the fully qualified message name: `name="testpkg.LoginRequest"`.

---

## Usage in Wireshark

1. Open Wireshark (or `tshark`).
2. Filter expressions:
   - Show protocol: `myname`
   - Filter by Packet ID: `myname.packetid == 1001`
   - Filter by Packet Name: `myname.packetname == "testpkg.LoginRequest"`
   - Search in decoded body (C++ plugin): `myname.body contains "alice"`

---

## Continuous Integration (CI)

The project includes automated GitHub Actions CI ([`.github/workflows/ci.yml`](file:///home/project/wireshark_protobuf_plugin/.github/workflows/ci.yml)) testing:
- **`libecho` Unit Tests** across Linux & Windows via `CTest`.
- **C++ Plugin End-to-End Test**: Compiles `evil.so`, loads into `tshark`, generates real synthetic PCAP, and verifies dissector output and filters.
- **Lua Plugin End-to-End Test**: Loads `packet-evil.lua` with `tshark -X lua_script:...`, dissects PCAP stream, and asserts field extraction.

---

## License

GPL-2.0-or-later (same as Wireshark).
