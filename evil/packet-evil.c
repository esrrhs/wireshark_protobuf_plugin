/* packet-evil.c
 *
 * Wireshark Protobuf Dissector Plugin
 * Supports Wireshark 3.x / 4.x
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>
#include <glib.h>
#include <stdio.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-tcp.h>

#include "libecho.h"
#include "packet-evil.h"
#include "evil_framing.h"

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
static int ett_evil = -1;

/* Expert info */
static expert_field ei_evil_invalid_len = EI_INIT;
static expert_field ei_evil_truncated   = EI_INIT;


/* -----------------------------------------------------------------------
 * Protocol constants
 *   Frame layout:
 *     [4 bytes datasize][2 bytes packetid][datasize-2 bytes body]
 *   Total frame = 4 + datasize  bytes
 *   Length policy (min / max / overflow) is in evil_framing.h
 * --------------------------------------------------------------------- */
#define FRAME_HDR_LEN        ((int)EVIL_FRAME_HDR_LEN)
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
static unsigned
get_evil_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
    /*
     * The 4-byte field holds the "data" portion size (packet-id + body).
     * The full frame is:  4 (length field) + datasize  bytes.
     *
     * tcp_dissect_pdus only calls this once at least FRAME_HDR_LEN bytes
     * are available.  A naive "return 4 + datasize" is unsafe:
     *   - datasize == 0xFFFFFFFF wraps a 32-bit unsigned to 3 (or 0 for
     *     0xFFFFFFFC), and a 0 / short return can infinite-loop in older
     *     tcp_dissect_pdus implementations;
     *   - a multi-gigabyte length would request unbounded TCP reassembly.
     *
     * Invalid lengths therefore consume the rest of this tvbuff (>=
     * FRAME_HDR_LEN) so the offset always advances.  dissect_evil_message
     * re-checks the length and marks the PDU malformed without decoding
     * the body.
     */
    uint32_t datasize = tvb_get_ntohl(tvb, offset + FRAME_SIZE_OFFSET);
    uint32_t total    = 0;
    int      remaining = tvb_reported_length_remaining(tvb, offset);

    if (!evil_pdu_try_len(datasize, &total)) {
        unsigned consume;

        if (remaining > FRAME_HDR_LEN)
            consume = (unsigned)remaining;
        else
            consume = (unsigned)FRAME_HDR_LEN;
        MYLOG("get_evil_message_len invalid datasize=%u, consume=%u",
              datasize, consume);
        return consume;
    }

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
    proto_item *ti, *pi_len;
    proto_tree *evil_tree;
    uint32_t    datasize;
    uint32_t    expected_total;
    uint16_t    packid;
    const char *msg_name;
    const char *body_str;
    int         body_len;
    unsigned    reported_len;
    unsigned    captured_len;
    char       *line, *saveptr;
    char       *body_copy;
    int         offset = 0;

    MYLOG("dissect_evil_message start, reported_length=%u captured=%u",
          tvb_reported_length(tvb), tvb_captured_length(tvb));

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "myname");
    col_clear(pinfo->cinfo, COL_INFO);

    reported_len = tvb_reported_length(tvb);
    captured_len = tvb_captured_length(tvb);

    /* Root tree item */
    ti        = proto_tree_add_item(tree, proto_evil, tvb, 0, -1, ENC_NA);
    evil_tree = proto_item_add_subtree(ti, ett_evil);

    /* Not even a complete length field: nothing more we can do. */
    if (captured_len < EVIL_LEN_FIELD_SIZE) {
        col_set_str(pinfo->cinfo, COL_INFO, "Truncated header");
        expert_add_info(pinfo, ti, &ei_evil_truncated);
        MYLOG("dissect_evil_message truncated before length field");
        return (int)captured_len;
    }

    /* --- 4-byte data size --- */
    datasize = tvb_get_ntohl(tvb, offset);
    pi_len   = proto_tree_add_uint(evil_tree, hf_evil_hdr_msg_datasize,
                                   tvb, offset, 4, datasize);
    offset += 4;

    /*
     * Invalid length (too small, overflow, or over the cap).  Do not
     * treat the rest as a protobuf body: this tvbuff may be the remainder
     * of the segment that get_evil_message_len consumed after a bad size.
     */
    if (!evil_pdu_try_len(datasize, &expected_total)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid data size %u", datasize);
        expert_add_info(pinfo, pi_len, &ei_evil_invalid_len);
        MYLOG("dissect_evil_message invalid datasize=%u", datasize);
        return (int)reported_len;
    }

    /* Header itself is truncated (have the size, not the packet-id). */
    if (captured_len < EVIL_FRAME_HDR_LEN) {
        col_set_str(pinfo->cinfo, COL_INFO, "Truncated header");
        expert_add_info(pinfo, ti, &ei_evil_truncated);
        MYLOG("dissect_evil_message truncated before packet-id");
        return (int)captured_len;
    }

    /* --- 2-byte packet id --- */
    packid   = tvb_get_ntohs(tvb, offset);
    msg_name = get_msg_name((int)packid);

    proto_tree_add_uint(evil_tree, hf_evil_hdr_msg_packetid,
                        tvb, offset, 2, packid);
    proto_tree_add_string(evil_tree, hf_evil_hdr_msg_packetname,
                          tvb, offset, 2, msg_name);

    col_add_fstr(pinfo->cinfo, COL_INFO, "PacketId=%u (%s)", packid, msg_name);
    offset += 2;

    /* --- protobuf body: only the bytes actually captured --- */
    body_len = tvb_captured_length_remaining(tvb, offset);
    if (captured_len < expected_total || reported_len < expected_total) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Truncated]");
        expert_add_info(pinfo, ti, &ei_evil_truncated);
    }

    if (body_len > 0) {
        const uint8_t *raw = tvb_get_ptr(tvb, offset, body_len);
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
    return (int)reported_len;
}

/* -----------------------------------------------------------------------
 * Top-level dissector  (handles TCP stream → PDUs)
 * --------------------------------------------------------------------- */
static int
dissect_evil(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     true,              /* desegment                  */
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

    static int *ett[] = {
        &ett_evil,
    };

    static ei_register_info ei[] = {
        { &ei_evil_invalid_len,
          { "myname.invalid_length", PI_MALFORMED, PI_ERROR,
            "Invalid data size", EXPFILL }
        },
        { &ei_evil_truncated,
          { "myname.truncated", PI_MALFORMED, PI_WARN,
            "Truncated message", EXPFILL }
        },
    };

    expert_module_t *expert_evil;

    MYLOG("proto_register_evil start");

    proto_evil = proto_register_protocol(
        "MyName Protocol",   /* long name  */
        "myname",            /* short name */
        "myname");           /* filter name */

    proto_register_field_array(proto_evil, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_evil = expert_register_protocol(proto_evil);
    expert_register_field_array(expert_evil, ei, array_length(ei));

    /* Register preferences so the port can be changed at runtime */
    prefs_register_protocol(proto_evil, proto_reg_handoff_evil);

    MYLOG("proto_register_evil done, proto_evil=%d", proto_evil);
}

/* -----------------------------------------------------------------------
 * Handoff – called once at startup and whenever preferences change
 * --------------------------------------------------------------------- */
static dissector_handle_t evil_handle = NULL;
static unsigned           last_port   = 0;

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

    dissector_add_uint("tcp.port", (uint32_t)port, evil_handle);
    last_port = (unsigned)port;

    MYLOG("proto_reg_handoff_evil done, port=%d", port);
}
