/* Copyright (c) 2026 freehelpdesk. Licensed under the MIT License.
 * See the LICENSE file in the repository root.
 */

#include "tesdec.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "smoke: %s\n", msg);
    return 1;
}

static int expect_offset(size_t got, size_t want, const char *field) {
    if (got != want) {
        fprintf(stderr, "smoke: %s offset %zu, want %zu\n", field, got, want);
        return 1;
    }
    return 0;
}

int main(void) {
    const char *version = tesdec_version();
    char err[256];
    int32_t kind = -1;
    int32_t rc;
    uint8_t key[8];
    struct tesdec_key_result out;

    if (version == NULL || version[0] == '\0') {
        return fail("empty version");
    }
    printf("tesdec %s\n", version);
    if (tesdec_max_batch() != TESDEC_MAX_BATCH) {
        return fail("max batch");
    }

    if (sizeof(struct tesdec_header) != 168) {
        return fail("header size");
    }
    if (sizeof(struct tesdec_key_request) != 56) {
        return fail("request size");
    }
    if (sizeof(struct tesdec_key_result) != 296) {
        return fail("result size");
    }
    if (expect_offset(offsetof(struct tesdec_header, plaintext_size), 0, "plaintext_size") ||
        expect_offset(offsetof(struct tesdec_header, timestamp), 8, "timestamp") ||
        expect_offset(offsetof(struct tesdec_header, key_id), 16, "key_id") ||
        expect_offset(offsetof(struct tesdec_header, reserved), 20, "reserved") ||
        expect_offset(offsetof(struct tesdec_header, public_key_len), 24, "public_key_len") ||
        expect_offset(offsetof(struct tesdec_header, wrapped_key_len), 32, "wrapped_key_len") ||
        expect_offset(offsetof(struct tesdec_header, vin), 40, "vin") ||
        expect_offset(offsetof(struct tesdec_header, public_key), 58, "public_key") ||
        expect_offset(offsetof(struct tesdec_header, wrapped_key), 123, "wrapped_key") ||
        expect_offset(offsetof(struct tesdec_key_request, vin), 0, "req.vin") ||
        expect_offset(offsetof(struct tesdec_key_request, public_key), 8, "req.public_key") ||
        expect_offset(offsetof(struct tesdec_key_request, wrapped_key), 16, "req.wrapped_key") ||
        expect_offset(offsetof(struct tesdec_key_request, timestamp), 24, "req.timestamp") ||
        expect_offset(offsetof(struct tesdec_key_request, public_key_len), 32, "req.public_key_len") ||
        expect_offset(offsetof(struct tesdec_key_request, wrapped_key_len), 40, "req.wrapped_key_len") ||
        expect_offset(offsetof(struct tesdec_key_request, key_id), 48, "req.key_id") ||
        expect_offset(offsetof(struct tesdec_key_result, key), 0, "result.key") ||
        expect_offset(offsetof(struct tesdec_key_result, key_len), 32, "result.key_len") ||
        expect_offset(offsetof(struct tesdec_key_result, error), 40, "result.error")) {
        return 1;
    }

    memset(err, 0, sizeof err);
    rc = tesdec_probe("/no/such/tesdec-clip.mp4", &kind, NULL, err, sizeof err);
    if (rc == TESDEC_OK) {
        return fail("missing path returned success");
    }
    if (err[0] == '\0') {
        return fail("missing path left err empty");
    }

    memset(key, 0, sizeof key);
    rc = tesdec_decrypt_file("a", "b", key, sizeof key, NULL, err, sizeof err);
    if (rc != TESDEC_ERR) {
        return fail("short key was accepted");
    }

    memset(&out, 0, sizeof out);
    rc = tesdec_fetch_keys(NULL, "token", NULL, 31, &out, err, sizeof err);
    if (rc != TESDEC_ERR) {
        return fail("batch of 31 was accepted");
    }
    rc = tesdec_fetch_keys(NULL, "token", NULL, 0, &out, err, sizeof err);
    if (rc != TESDEC_ERR) {
        return fail("empty batch was accepted");
    }

    printf("ok\n");
    return 0;
}
