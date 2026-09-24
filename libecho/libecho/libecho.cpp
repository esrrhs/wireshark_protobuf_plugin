// libecho.cpp
//
// Helper library: loads config.xml, imports a .proto file at runtime,
// and uses the Protobuf reflection API to decode binary messages.
//
// Compatible with protobuf 3.x and 4.x (protobuf 3.21+).
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include "libecho.h"

#include <cstdio>
#include <ctime>
#include <cstring>
#include <cstdarg>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "config.h"

using namespace google::protobuf;
using namespace google::protobuf::compiler;

/* -----------------------------------------------------------------------
 * File logger
 * --------------------------------------------------------------------- */
static void
MyLog(const char *file, const char *func, int line, const char *fmt, ...)
{
    FILE   *fp = fopen("evil.log", "a+");
    if (!fp) return;

    time_t t = time(nullptr);
    struct tm *ti = localtime(&t);
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] %s:%d %s: ",
            ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
            ti->tm_hour, ti->tm_min, ti->tm_sec,
            file, line, func);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fclose(fp);
}
#define MYLOG(...) MyLog(__FILE__, __func__, __LINE__, __VA_ARGS__)

/* -----------------------------------------------------------------------
 * Error collector: silently swallows protobuf import warnings/errors
 * (replace with a logging version if needed for debugging).
 * --------------------------------------------------------------------- */
class SilentErrorCollector : public MultiFileErrorCollector
{
public:
    void AddError(const std::string &filename, int line, int column,
                  const std::string &message) override
    {
        MYLOG("Proto error %s:%d:%d: %s",
              filename.c_str(), line, column, message.c_str());
    }

    void AddWarning(const std::string &filename, int line, int column,
                    const std::string &message) override
    {
        MYLOG("Proto warning %s:%d:%d: %s",
              filename.c_str(), line, column, message.c_str());
    }
};

/* -----------------------------------------------------------------------
 * Global state
 * --------------------------------------------------------------------- */
static CMsgLoader                    g_config;
static std::map<int, std::string>    g_msgMap;   // id → message type name
static std::string                   g_result;   // scratch buffer for C API
static DiskSourceTree               *g_sourceTree = nullptr;
static SilentErrorCollector         *g_errCollector = nullptr;
static Importer                     *g_importer  = nullptr;
static DynamicMessageFactory        *g_factory   = nullptr;

/* -----------------------------------------------------------------------
 * C API: ini_msg
 *   Reads config.xml, imports the .proto file, builds the descriptor map.
 * --------------------------------------------------------------------- */
extern "C" void ini_msg()
{
    if (!g_config.LoadCfg("config.xml")) {
        MYLOG("LoadCfg failed – aborting");
        return;
    }

    const std::string &protoname = g_config.GetMsg().m_STConfig.m_strproto;
    MYLOG("proto file: %s", protoname.c_str());

    delete g_factory;     g_factory     = nullptr;
    delete g_importer;    g_importer    = nullptr;
    delete g_errCollector; g_errCollector = nullptr;
    delete g_sourceTree;  g_sourceTree  = nullptr;

    g_sourceTree   = new DiskSourceTree();
    g_sourceTree->MapPath("", "./");   // look up .proto in CWD

    g_errCollector = new SilentErrorCollector();
    g_importer     = new Importer(g_sourceTree, g_errCollector);
    g_factory      = new DynamicMessageFactory();

    const FileDescriptor *fd = g_importer->Import(protoname);
    if (!fd) {
        MYLOG("Failed to import %s", protoname.c_str());
        return;
    }

    g_msgMap.clear();
    const auto &msgs = g_config.GetMsg().m_vecSTMsgId;
    for (const auto &entry : msgs) {
        int         id   = entry.m_iid;
        std::string name = entry.m_strname;

        // Try with package prefix first, then bare name
        const Descriptor *desc =
            g_importer->pool()->FindMessageTypeByName(name);
        if (!desc) {
            // Try common package prefixes from the config
            std::string qualified = "ntesgame." + name;
            desc = g_importer->pool()->FindMessageTypeByName(qualified);
        }
        if (!desc) {
            MYLOG("FindMessageTypeByName(%s) failed", name.c_str());
            continue;
        }

        g_msgMap[id] = desc->full_name();
        MYLOG("Registered id=%d name=%s", id, desc->full_name().c_str());
    }

    MYLOG("ini_msg done, %zu messages registered", g_msgMap.size());
}

/* -----------------------------------------------------------------------
 * C API: get_msg_name
 * --------------------------------------------------------------------- */
extern "C" const char *get_msg_name(int id)
{
    auto it = g_msgMap.find(id);
    if (it != g_msgMap.end()) {
        g_result = it->second;
        return g_result.c_str();
    }
    return "unknown";
}

/* -----------------------------------------------------------------------
 * C API: show_msg
 *   Deserializes binary proto data and returns a human-readable string.
 * --------------------------------------------------------------------- */
extern "C" const char *show_msg(int id, const char *data, int srclen)
{
    if (!g_importer || !g_factory) {
        return "(not initialized)";
    }

    auto it = g_msgMap.find(id);
    if (it == g_msgMap.end()) {
        return "(unknown message id)";
    }

    const Descriptor *desc =
        g_importer->pool()->FindMessageTypeByName(it->second);
    if (!desc) {
        return "(descriptor not found)";
    }

    const Message *prototype = g_factory->GetPrototype(desc);
    if (!prototype) {
        return "(no prototype)";
    }

    Message *msg = prototype->New();
    if (!msg->ParseFromArray(data, srclen)) {
        delete msg;
        return "(ParseFromArray failed – malformed data?)";
    }

    // Use TextFormat for a stable, UTF-8 safe output
    g_result.clear();
    if (!TextFormat::PrintToString(*msg, &g_result)) {
        delete msg;
        return "(TextFormat::PrintToString failed)";
    }

    delete msg;
    return g_result.c_str();
}

/* -----------------------------------------------------------------------
 * C API: get_port
 * --------------------------------------------------------------------- */
extern "C" int get_port()
{
    return g_config.GetMsg().m_STConfig.m_iport;
}
