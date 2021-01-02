#ifndef H_OCB_BLOCKCIPHER_H
#define H_OCB_BLOCKCIPHER_H

/* Wrapper for a generic block cipher. Block size must be 128 bits (16 bytes) */

/* 
   The current block cipher implementation used. You may switch this with a different include of a different
   block cipher implementation, if one wants to.
*/
#include "cipher/aes.h" // Include your own block cipher here.

#define OCB_BLOCK_SIZE 16 /* Block size by which everything from L_offsets to the underlying block cipher's block size use. It is
                         recommended to be kept 16, as most block ciphers are 16 byte block-based anyway. */
#define OCB_BLOCK_SIZE_BITS (BLOCK_SIZE * 8) /* 128 bits */

#define OCB_BLOCKCIPHER_ENC 1
#define OCB_BLOCKCIPHER_DEC 0

#define OCB_BLOCKCIPHER_OK 1
#define OCB_BLOCKCIPHER_ERR 0

typedef mbedtls_aes_context blockcipher_ctx; /* Change to your block cipher of choice context. */

/* Generic OCB block cipher initialization routine. */
static void ocb_blockcipher_init(blockcipher_ctx* ctx)
{
    mbedtls_aes_init(ctx);
}

/* Generic OCB block cipher free routine. */
static void ocb_blockcipher_free(blockcipher_ctx* ctx)
{
    mbedtls_aes_free(ctx);
}

/* Generic OCB block cipher setup key routine. */
static int ocb_blockcipher_set_key(blockcipher_ctx* ctx, int mode, const uint8_t* key, const size_t keybits)
{
    int result;

    if (mode == OCB_BLOCKCIPHER_ENC)
        result = mbedtls_aes_setkey_enc(ctx, key, keybits);
    else
        result = mbedtls_aes_setkey_dec(ctx, key, keybits);

    if (result != 0)
        return OCB_BLOCKCIPHER_ERR;

    return OCB_BLOCKCIPHER_OK;
}

/* Generic OCB block cipher block encryption routine. */
static int ocb_blockcipher_crypt_block(blockcipher_ctx* ctx, int mode, uint8_t output[OCB_BLOCK_SIZE], uint8_t input[OCB_BLOCK_SIZE])
{
    int result, mbedtls_mode;

    if (mode == OCB_BLOCKCIPHER_ENC)
        mbedtls_mode = MBEDTLS_AES_ENCRYPT;
    else
        mbedtls_mode = MBEDTLS_AES_DECRYPT;

    result = mbedtls_aes_crypt_ecb(ctx, mbedtls_mode, input, output);

    if (result != 0)
        return OCB_BLOCKCIPHER_ERR;

    return OCB_BLOCKCIPHER_OK;
}

#endif H_OCB_BLOCKCIPHER_h