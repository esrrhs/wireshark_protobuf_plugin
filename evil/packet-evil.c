/* packet-evil.c
 *
 * Wireshark Protobuf Dissector Plugin
 * Supports Wireshark 3.x / 4.x
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/proto.h>

#include "packet-evil.h"

/* -----------------------------------------------------------------------
 * Protocol handle
 * --------------------------------------------------------------------- */
static int proto_evil = -1;

/* Header field handles */
static int hf_evil_hdr_msg_datasize  = -1;
static int hf_evil_hdr_msg_packetid  = -1;
static int hf_evil_hdr_msg_packetname = -1;
static int hf_evil_hdr_msg_body      = -1;

/* Subtree handles */
static gint ett_evil = -1;

/* -----------------------------------------------------------------------
 * Protocol constants
 *   Frame layout:
 *     [4 bytes datasize][2 bytes packetid][datasize-2 bytes body]
 *   Total frame = 4 + datasize  bytes
 * --------------------------------------------------------------------- */
#define FRAME_HDR_LEN        6   /* 4-byte length + 2-byte packet-id    */
#define FRAME_SIZE_OFFSET    0   /* offset of the 4-byte length field   */
#define FRAME_ID_OFFSET      4   /* offset of the 2-byte packet-id      */
#define FRAME_BODY_OFFSET    6   /* offset of the protobuf body         */

/* -----------------------------------------------------------------------
 * Simple file logger
 * --------------------------------------------------------------------- */
#ifdef EVIL_DEBUG_LOG
static void
my_log(const char *file, const char *func, int line, const char *fmt, ...)
{
    FILE   *fp;
    time_t  t = time(NULL);
    struct tm *tm_info = localtime(&t);
    va_list ap;

    fp = fopen("evil.log", "a+");
    if (!fp)
        return;

    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] %s:%d %s: ",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
            file, line, func);

    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fclose(fp);
}
#define MYLOG(...) my_log(__FILE__, __func__, __LINE__, __VA_ARGS__)
#else
#define MYLOG(...) do {} while (0)
#endif /* EVIL_DEBUG_LOG */

/* -----------------------------------------------------------------------
 * PDU length callback  (called by tcp_dissect_pdus)
 * --------------------------------------------------------------------- */
static guint
get_evil_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
    /*
     * The 4-byte field holds the "data" portion size (packet-id + body).
     * The full frame is:  4 (length field) + datasize  bytes.
     */
    guint32 datasize = tvb_get_ntohl(tvb, offset + FRAME_SIZE_OFFSET);
    guint   total    = 4 + datasize;

    MYLOG("get_evil_message_len datasize=%u total=%u", datasize, total);
    return total;
}

/* -----------------------------------------------------------------------
 * Per-message dissector
 * --------------------------------------------------------------------- */
static int
dissect_evil_message(tvbuff_t *tvb, packet_info *pinfo,
                     proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *evil_tree;
    guint32     datasize;
    guint16     packid;
    const char *msg_name;
    const char *body_str;
    int         body_len;
    guint       total_len;
    char       *line, *saveptr;
    char       *body_copy;
    int         offset = 0;

    MYLOG("dissect_evil_message start, reported_length=%u",
          tvb_reported_length(tvb));

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "myname");
    col_clear(pinfo->cinfo, COL_INFO);

    total_len = tvb_reported_length(tvb);

    /* Root tree item */
    ti        = proto_tree_add_item(tree, proto_evil, tvb, 0, -1, ENC_NA);
    evil_tree = proto_item_add_subtree(ti, ett_evil);

    /* --- 4-byte data size --- */
    datasize = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(evil_tree, hf_evil_hdr_msg_datasize,
                        tvb, offset, 4, datasize);
    offset += 4;

    /* --- 2-byte packet id --- */
    packid   = tvb_get_ntohs(tvb, offset);
    msg_name = get_msg_name((int)packid);

    proto_tree_add_uint(evil_tree, hf_evil_hdr_msg_packetid,
                        tvb, offset, 2, packid);
    proto_tree_add_string(evil_tree, hf_evil_hdr_msg_packetname,
                          tvb, offset, 2, msg_name);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PacketId=%u (%s)", packid, msg_name);
    offset += 2;

    /* --- protobuf body --- */
    body_len = (int)total_len - offset;
    if (body_len > 0) {
        const guint8 *raw = tvb_get_ptr(tvb, offset, body_len);
        body_str  = show_msg((int)packid, (const char *)raw, body_len);

        /* Split multi-line body into individual tree entries */
        body_copy = g_strdup(body_str ? body_str : "");
        line = strtok_r(body_copy, "\n", &saveptr);
        while (line) {
            proto_tree_add_string(evil_tree, hf_evil_hdr_msg_body,
                                  tvb, offset, body_len, line);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        g_free(body_copy);
    }

    MYLOG("dissect_evil_message done");
    return (int)total_len;
}

/* -----------------------------------------------------------------------
 * Top-level dissector  (handles TCP stream → PDUs)
 * --------------------------------------------------------------------- */
static int
dissect_evil(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     TRUE,              /* desegment                  */
                     FRAME_HDR_LEN,     /* fixed header size          */
                     get_evil_message_len,
                     dissect_evil_message,
                     data);
    return (int)tvb_reported_length(tvb);
}

/* -----------------------------------------------------------------------
 * Protocol registration
 * --------------------------------------------------------------------- */
void
proto_register_evil(void)
{
    static hf_register_info hf[] = {
        { &hf_evil_hdr_msg_datasize,
          { "Data Size", "myname.datasize",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Size of the message data (packet-id + body)", HFILL }
        },
        { &hf_evil_hdr_msg_packetid,
          { "Packet ID", "myname.packetid",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Numeric identifier of the message type", HFILL }
        },
        { &hf_evil_hdr_msg_packetname,
          { "Packet Name", "myname.packetname",
            FT_STRING, BASE_NONE, NULL, 0,
            "Name of the message type from config.xml", HFILL }
        },
        { &hf_evil_hdr_msg_body,
          { "Body", "myname.body",
            FT_STRING, BASE_NONE, NULL, 0,
            "Decoded Protobuf body (one field per row)", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_evil,
    };

    MYLOG("proto_register_evil start");

    proto_evil = proto_register_protocol(
        "MyName Protocol",   /* long name  */
        "myname",            /* short name */
        "myname");           /* filter name */

    proto_register_field_array(proto_evil, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences so the port can be changed at runtime */
    prefs_register_protocol(proto_evil, proto_reg_handoff_evil);

    MYLOG("proto_register_evil done, proto_evil=%d", proto_evil);
}

/* -----------------------------------------------------------------------
 * Handoff – called once at startup and whenever preferences change
 * --------------------------------------------------------------------- */
static dissector_handle_t evil_handle = NULL;
static guint              last_port   = 0;

void
proto_reg_handoff_evil(void)
{
    int port;

    MYLOG("proto_reg_handoff_evil start");

    ini_msg();
    port = get_port();

    if (evil_handle == NULL) {
        evil_handle = create_dissector_handle(dissect_evil, proto_evil);
    }

    if (last_port != 0) {
        dissector_delete_uint("tcp.port", last_port, evil_handle);
    }

    dissector_add_uint("tcp.port", (guint)port, evil_handle);
    last_port = (guint)port;

    MYLOG("proto_reg_handoff_evil done, port=%d", port);
}
