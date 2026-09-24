# wireshark-protobuf-plugin

A **Wireshark dissector plugin** that decodes custom TCP streams carrying
[Protocol Buffers (protobuf)](https://protobuf.dev/) messages at runtime –
no code generation required.

Supports **Wireshark 3.x / 4.x** on Linux and Windows.

---

## How it works

```
TCP packet
  ┌─────────────────────────────────────────────────┐
  │ 4 bytes │  2 bytes  │  N bytes                  │
  │ datasize│ packet-id │  protobuf body (N = datasize-2) │
  └─────────────────────────────────────────────────┘
```

1. The plugin reads `config.xml` to learn the TCP **port**, the `.proto`
   filename, and the **packet-id → message-name** mapping.
2. At capture time it imports the `.proto` file via the protobuf reflection
   API (no `protoc` invocation needed) and deserialises every message on the
   fly.
3. Each field is shown as a child node in the Wireshark packet tree.

---

## Repository layout

```
wireshark_protobuf_plugin/
├── evil/               Wireshark dissector plugin (C)
│   ├── packet-evil.c   Dissector – main dissection logic
│   ├── plugin.c        Wireshark plugin entry points
│   ├── packet-evil.h
│   ├── moduleinfo.h
│   └── CMakeLists.txt  (integrated into Wireshark source tree)
├── libecho/            C++ helper library
│   ├── CMakeLists.txt  (standalone build)
│   ├── libecho/
│   │   ├── libecho.h   C API exposed to the dissector
│   │   ├── libecho.cpp Protobuf reflection + XML config loader
│   │   ├── config.h    Auto-generated XML config class
│   │   ├── tinyxml.*   Embedded TinyXML parser
│   │   └── tinystr.*
│   └── test/
│       └── test.cpp    Simple smoke-test
├── config.xml          Runtime config (copy to Wireshark plugin dir)
└── README.md
```

---

## Build

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| CMake | 3.16 |
| C compiler | GCC 9 / Clang 10 / MSVC 2019 |
| C++ compiler | same, with C++17 support |
| Wireshark source | 3.6 or 4.x |
| protobuf | 3.12+ (or 4.x / protobuf 3.21+) |

### Step 1 – build libecho

```bash
cd libecho
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# produces build/libecho.a  (or libecho.lib on Windows)
```

### Step 2 – integrate with the Wireshark source tree

```bash
# Download the Wireshark source that matches your installed binary:
# https://www.wireshark.org/download.html

# Copy the plugin folder into the Wireshark source tree:
cp -r evil  <wireshark-src>/plugins/epan/

# Register the plugin in the Wireshark top-level CMakeLists.txt.
# Find the block that lists epan plugins and add "evil":
#   plugins/epan/evil
# (exact location depends on the Wireshark version)
```

Edit `<wireshark-src>/CMakeLists.txt` – find:
```cmake
set(PLUGIN_SRC_DIRS
    plugins/epan/ethercat
    plugins/epan/gryphon
    ...
)
```
and add:
```cmake
    plugins/epan/evil
```

### Step 3 – configure and build Wireshark with the plugin

```bash
cd <wireshark-src>
cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DENABLE_PLUGINS=ON \
      -Dlibecho_DIR=<absolute-path-to>/libecho/build
cmake --build build --target evil
```

The resulting shared library is placed in:
```
build/run/plugins/<version>/epan/evil.so   # Linux
build/run/plugins/<version>/epan/evil.dll  # Windows
```

---

## Runtime setup

Copy the following files into your Wireshark **plugin directory**
(`Help → About Wireshark → Folders → Personal Plugins`):

```
evil.so / evil.dll
config.xml
YourProtos.proto
```

### config.xml format

```xml
<Msg>
  <Config port="8888"
          proto="YourProtos.proto"
          clientregid="1"
          serverregid="101"
          regkey="aaa"
          key="bbb"/>

  <!-- Map numeric packet-ids to proto message names -->
  <MsgId id="1"  name="LoginRequest"/>
  <MsgId id="2"  name="LoginResponse"/>
</Msg>
```

> **Note:** The `name` attribute must match a top-level message name in
> your `.proto` file.  If your messages live in a package (e.g.
> `package mygame;`), write the **fully-qualified** name:
> `name="mygame.LoginRequest"`.

---

## Usage in Wireshark

1. Restart Wireshark after placing the files.
2. In the display filter bar, type `myname` to show only your protocol.
3. Useful filters:
   - `myname.packetid == 1`
   - `myname.packetname == "LoginRequest"`
   - `myname.body contains "user_id"`

---

## Debug logging

Compile with `-DEVIL_DEBUG_LOG` to enable file logging:

```cmake
target_compile_definitions(evil PRIVATE EVIL_DEBUG_LOG)
```

Log files are written to the directory from which Wireshark is launched:
- `evil.log` – libecho runtime log
- `evil.log` – dissector log (same file, different prefix lines)

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Plugin not loaded | Check `Help → About → Plugins`. Ensure `.so`/`.dll` is in the right folder for your Wireshark version (`epan/` sub-dir required on 4.x). |
| `(not initialized)` in body | `config.xml` or the `.proto` file is missing from the plugin dir. |
| `(ParseFromArray failed)` | The raw bytes aren't valid for that message type. Check endianness / header offsets in `packet-evil.c`. |
| ABI mismatch crash | Rebuild the plugin against the **exact** Wireshark source that matches your binary. |

---

## License

GPL-2.0-or-later (same as Wireshark).
