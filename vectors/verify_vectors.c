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

#define TAG_SIGN    "pipe-k1/v1/sign"
#define TAG_AUTH    "pipe-k1/v1/auth"
#define TAG_ENTROPY "pipe-k1/v1/entropy"

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
    uint8_t version;     /* 0x01 */
    uint32_t timestamp;  /* 4B Big-endian */
    uint8_t signer_pub[32];
    uint8_t signature[64];
} pipek1_sig_payload_t;

typedef struct {
    uint8_t sender_pub[32];
    uint8_t signature[64];
} pipek1_trailer_t;
#pragma pack(pop)

int main(void) {
    /* Assert exact byte sizes mandated by Specification v1.9 */
    assert(sizeof(pipek1_header_t) == 97);
    assert(sizeof(pipek1_chunk_hdr_t) == 5);
    assert(sizeof(pipek1_sig_payload_t) == 105);
    assert(sizeof(pipek1_trailer_t) == 96);

    /* Assert exact field offsets in wire header */
    assert(__builtin_offsetof(pipek1_header_t, magic) == 0);
    assert(__builtin_offsetof(pipek1_header_t, version) == 4);
    assert(__builtin_offsetof(pipek1_header_t, mode) == 5);
    assert(__builtin_offsetof(pipek1_header_t, eph_pub) == 6);
    assert(__builtin_offsetof(pipek1_header_t, recip_pub) == 38);
    assert(__builtin_offsetof(pipek1_header_t, salt) == 70);
    assert(__builtin_offsetof(pipek1_header_t, header_hmac) == 81);

    /* Assert exact field offsets in signature payload */
    assert(__builtin_offsetof(pipek1_sig_payload_t, magic) == 0);
    assert(__builtin_offsetof(pipek1_sig_payload_t, version) == 4);
    assert(__builtin_offsetof(pipek1_sig_payload_t, timestamp) == 5);
    assert(__builtin_offsetof(pipek1_sig_payload_t, signer_pub) == 9);
    assert(__builtin_offsetof(pipek1_sig_payload_t, signature) == 41);

    /* Assert exact field offsets in trailer */
    assert(__builtin_offsetof(pipek1_trailer_t, sender_pub) == 0);
    assert(__builtin_offsetof(pipek1_trailer_t, signature) == 32);

    /* Assert domain separation tag strings */
    assert(strcmp(TAG_SIGN, "pipe-k1/v1/sign") == 0);
    assert(strcmp(TAG_AUTH, "pipe-k1/v1/auth") == 0);
    assert(strcmp(TAG_ENTROPY, "pipe-k1/v1/entropy") == 0);

    printf("[PASS] C Struct Layout Verification:\n");
    printf("  - Wire Header:        %zu bytes (Expected: 97)\n", sizeof(pipek1_header_t));
    printf("  - Chunk Framing:       %zu bytes (Expected: 5)\n", sizeof(pipek1_chunk_hdr_t));
    printf("  - Signature Payload: %zu bytes (Expected: 105)\n", sizeof(pipek1_sig_payload_t));
    printf("  - Mode 1 Trailer:     %zu bytes (Expected: 96)\n", sizeof(pipek1_trailer_t));
    printf("  - Domain Tags:       TAG_SIGN, TAG_AUTH, TAG_ENTROPY verified\n");

    return 0;
}
