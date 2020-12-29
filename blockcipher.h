#ifndef H_OCB_BLOCKCIPHER_H
#define H_OCB_BLOCKCIPHER_H

/* Wrapper for a generic block cipher. Block size must be 128 bits (16 bytes) */

/* 
   The current block cipher implementation used. You may switch this with a different include of a different
   block cipher implementation, if one wants to.
*/
#include "cipher/aes.h"

#define BLOCK_SIZE 16
#define BLOCK_SIZE_BITS (BLOCK_SIZE * 8)

#define BLOCKCIPHER_ENC 1
#define BLOCKCIPHER_DEC 0

#define BLOCKCIPHER_OK 1
#define BLOCKCIPHER_ERR 0

typedef mbedtls_aes_context blockcipher_ctx; /* Change to your ctx block cipher of choice context. */

static void blockcipher_init(blockcipher_ctx* ctx)
{
    mbedtls_aes_init(ctx);
}

static void blockcipher_free(blockcipher_ctx* ctx)
{
    mbedtls_aes_free(ctx);
}

static int blockcipher_set_key(blockcipher_ctx* ctx, int mode, const uint8_t* key, const size_t keybits)
{
    int result;

    if (mode == BLOCKCIPHER_ENC)
        result = mbedtls_aes_setkey_enc(ctx, key, keybits);
    else
        result = mbedtls_aes_setkey_dec(ctx, key, keybits);

    if (result != 0)
        return BLOCKCIPHER_ERR;

    return BLOCKCIPHER_OK;
}

static int blockcipher_crypt_block(blockcipher_ctx* ctx, int mode, uint8_t output[BLOCK_SIZE], uint8_t input[BLOCK_SIZE])
{
    int result, mbedtls_mode;

    if (mode == BLOCKCIPHER_ENC)
        mbedtls_mode = MBEDTLS_AES_ENCRYPT;
    else
        mbedtls_mode = MBEDTLS_AES_DECRYPT;

    result = mbedtls_aes_crypt_ecb(ctx, mbedtls_mode, input, output);

    if (result != 0)
        return BLOCKCIPHER_ERR;

    return BLOCKCIPHER_OK;
}

#endif H_OCB_BLOCKCIPHER_h