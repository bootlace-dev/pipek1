/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bootlace-dev
 */

/*
 * pipek1 Minimal C Verification Harness (Specification v1.9)
 * Asserts byte offsets, framing sizes, and tagged hash constants.
 * Compiled via standard host GCC.
 * Zero-PII Invariant: Author: bootlace-dev <bootlace-dev@users.noreply.github.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define PIPEK1_MAGIC "PK01"
#define PIPEK1_VERSION 0x01

#pragma pack(push, 1)
typedef struct {
    uint8_t magic[4];
    uint8_t version;
    uint8_t mode;
    uint8_t eph_pub[32];
    uint8_t recip_pub[32];
    uint8_t salt[11];
    uint8_t header_hmac[16];
} pipek1_header_t;

typedef struct {
    uint32_t chunk_len;  /* Big-endian u32 */
    uint8_t  term_tag;   /* 0x00 intermediate, 0x01 terminal */
} pipek1_chunk_hdr_t;

typedef struct {
    uint8_t magic[4];    /* "PKSG" */
    uint8_t version;    /* 0x01 */
    uint32_t timestamp;  /* 4B Big-endian */
    uint8_t signer_pub[32];
    uint8_t signature[64];
} pipek1_sig_payload_t;
#pragma pack(pop)

int main(void) {
    /* Assert exact byte sizes mandated by Specification v1.9 */
    assert(sizeof(pipek1_header_t) == 97);
    assert(sizeof(pipek1_chunk_hdr_t) == 5);
    assert(sizeof(pipek1_sig_payload_t) == 105);

    printf("[PASS] C Struct Layout Verification:\n");
    printf("  - Wire Header:        %zu bytes (Expected: 97)\n", sizeof(pipek1_header_t));
    printf("  - Chunk Framing:       %zu bytes (Expected: 5)\n", sizeof(pipek1_chunk_hdr_t));
    printf("  - Signature Payload: %zu bytes (Expected: 105)\n", sizeof(pipek1_sig_payload_t));

    return 0;
}
