/*
 * plugin.c  –  Wireshark plugin entry points
 *
 * Compatible with Wireshark 4.x plugin ABI (plugin_want_major/minor +
 * plugin_describe). Mirrors tools/make-plugin-reg.py output.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <gmodule.h>

/* plugins are DLLs on Windows / shared objects on UN*X */
#define WS_BUILD_DLL
#include <ws_symbol_export.h>
#include <wsutil/plugins.h>
#include <epan/proto.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC

#ifdef __cplusplus
extern "C" {
#endif

/* Use WS_DLL_PUBLIC_DEF for data *definitions* (WS_DLL_PUBLIC adds extern).
 * Must match make-plugin-reg.py: VERSION_MAJOR/MINOR from Wireshark config.h. */
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int  plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int  plugin_want_minor = VERSION_MINOR;

extern void proto_register_evil(void);
extern void proto_reg_handoff_evil(void);

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_evil;
    plug.register_handoff   = proto_reg_handoff_evil;
    proto_register_plugin(&plug);
}

#ifdef __cplusplus
}
#endif

#endif /* ENABLE_STATIC */
