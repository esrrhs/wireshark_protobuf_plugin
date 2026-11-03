/*
 * plugin.c  –  Wireshark plugin entry points
 *
 * Compatible with Wireshark 4.x plugin ABI (also works on 3.6+ with
 * plugin_want_major / plugin_want_minor).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL

#include "config.h"

#include <wireshark.h>
#include <epan/proto.h>
#include <wsutil/plugins.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC

/* Use WS_DLL_PUBLIC_DEF for data *definitions* (WS_DLL_PUBLIC adds extern). */
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int  plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int  plugin_want_minor = WIRESHARK_VERSION_MINOR;

extern void proto_register_evil(void);
extern void proto_reg_handoff_evil(void);

WS_DLL_PUBLIC void plugin_register(void);
#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_evil;
    plug.register_handoff   = proto_reg_handoff_evil;
    proto_register_plugin(&plug);
}

#ifdef WS_PLUGIN_DESC_DISSECTOR
uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}
#endif

#endif /* ENABLE_STATIC */
