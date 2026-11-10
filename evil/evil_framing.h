/*
 * evil_framing.h
 *
 * Pure PDU-length policy shared by the C dissector (packet-evil.c).
 * Keep in sync with the "-- BEGIN EVIL_FRAMING" block in lua/packet-evil.lua.
 *
 * Frame layout:
 *   [4-byte BE datasize][2-byte BE packet-id][datasize-2 bytes body]
 * Total on-wire length = 4 + datasize.  Minimum valid datasize is 2.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EVIL_FRAMING_H
#define EVIL_FRAMING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 4-byte length field + 2-byte packet-id */
#define EVIL_LEN_FIELD_SIZE  4u
#define EVIL_ID_FIELD_SIZE   2u
#define EVIL_FRAME_HDR_LEN   6u
#define EVIL_MIN_DATASIZE    2u

/*
 * Upper bound on a single PDU (length field + payload).
 * Large enough for ordinary application protobuf messages, small enough
 * to reject clearly bogus length fields (e.g. 0xFFFFFFFF) that would
 * wrap a 32-bit 4+datasize or ask TCP reassembly for gigabytes.
 */
#define EVIL_MAX_PDU_LEN     (16u * 1024u * 1024u)

/*
 * If datasize is a usable length field, write 4+datasize to *out_total
 * and return 1.  Return 0 if the length is too small, would overflow,
 * or exceeds EVIL_MAX_PDU_LEN.  Never adds 4+datasize when it could wrap.
 */
static inline int
evil_pdu_try_len(uint32_t datasize, uint32_t *out_total)
{
    if (datasize < EVIL_MIN_DATASIZE)
        return 0;
    if (datasize > EVIL_MAX_PDU_LEN - EVIL_LEN_FIELD_SIZE)
        return 0;
    if (out_total)
        *out_total = EVIL_LEN_FIELD_SIZE + datasize;
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* EVIL_FRAMING_H */
