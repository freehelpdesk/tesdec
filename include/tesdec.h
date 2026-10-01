#ifndef TESDEC_H
#define TESDEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(TESDEC_DLL)
#define TESDEC_API __declspec(dllimport)
#else
#define TESDEC_API
#endif

/* 0 on success. 1 on a local or HTTP failure. 2 when Tesla rejects the token. */
#define TESDEC_OK 0
#define TESDEC_ERR 1
#define TESDEC_UNAUTHORIZED 2

/* tesdec_probe kind. */
#define TESDEC_PLAIN 0
#define TESDEC_ENCRYPTED 1

/* One decrypt/batch request. The live service rejects a larger body. */
#define TESDEC_MAX_BATCH 30
#define TESDEC_VIN_LEN 17
#define TESDEC_PUBKEY_MAX 65
#define TESDEC_WRAPPED_LEN 44

/*
 * LP64 layout, 168 bytes. vin is 17 ASCII bytes and a trailing NUL.
 * public_key_len and wrapped_key_len say how many leading bytes are live.
 */
typedef struct tesdec_header {
    uint64_t plaintext_size;
    uint64_t timestamp;
    uint32_t key_id;
    uint32_t reserved;
    uint64_t public_key_len;
    uint64_t wrapped_key_len;
    char vin[18];
    uint8_t public_key[65];
    uint8_t wrapped_key[44];
} tesdec_header;

/* Pointers are borrowed for the duration of tesdec_fetch_keys. 56 bytes. */
typedef struct tesdec_key_request {
    const char *vin;
    const uint8_t *public_key;
    const uint8_t *wrapped_key;
    uint64_t timestamp;
    uint64_t public_key_len;
    uint64_t wrapped_key_len;
    uint32_t key_id;
    uint32_t pad;
} tesdec_key_request;

/*
 * Filled only when tesdec_fetch_keys returns TESDEC_OK.
 * key_len is 16 or 32 on success. Otherwise error is a NUL-terminated message
 * and key_len is 0. 296 bytes.
 */
typedef struct tesdec_key_result {
    uint8_t key[32];
    uint64_t key_len;
    char error[256];
} tesdec_key_result;

/* Static NUL-terminated version string. Valid for the life of the process. */
TESDEC_API const char *tesdec_version(void);

/* Same value as TESDEC_MAX_BATCH. */
TESDEC_API uint32_t tesdec_max_batch(void);

/*
 * Classify path. On success kind is TESDEC_PLAIN or TESDEC_ENCRYPTED.
 * An encrypted clip requires header. A plain clip may pass a null header;
 * a non-null header is zeroed. If the clip is encrypted and header is null,
 * kind is set to TESDEC_ENCRYPTED and the call returns TESDEC_ERR.
 * err may be null. Otherwise it receives a NUL-terminated UTF-8 message.
 * Paths are filesystem bytes on Unix and UTF-8 elsewhere.
 */
TESDEC_API int32_t tesdec_probe(
    const char *path,
    int32_t *kind,
    struct tesdec_header *header,
    char *err,
    uint64_t err_len);

/*
 * Decrypt one clip. key_len is 16 or 32. written may be null and receives
 * the plaintext length. The destination is replaced only after the decrypted
 * bytes start with an MP4 ftyp box.
 */
TESDEC_API int32_t tesdec_decrypt_file(
    const char *src,
    const char *dest,
    const uint8_t *key,
    uint64_t key_len,
    uint64_t *written,
    char *err,
    uint64_t err_len);

/*
 * Fetch one AES key per clip. api_base null uses https://dashcam.tesla.com.
 * bearer is an access token, with or without a "Bearer " prefix. This call
 * does not open a sign-in window. count is 1 to TESDEC_MAX_BATCH.
 * On TESDEC_OK, out[i] matches items[i]. On any other status, out is not written.
 * These functions may be called from more than one thread.
 */
TESDEC_API int32_t tesdec_fetch_keys(
    const char *api_base,
    const char *bearer,
    const struct tesdec_key_request *items,
    uint64_t count,
    struct tesdec_key_result *out,
    char *err,
    uint64_t err_len);

#ifdef __cplusplus
}
#endif

#endif
