#ifndef H_OCB_H
#define H_OCB_H

#include<string.h>
#include<stdint.h>
#include<stdlib.h>

#include "blockcipher.h"

#define TAGLEN_BITS 128
#define TAGLEN TAGLEN_BITS / 8

#define OCB_ENC 1
#define OCB_DEC 0

/* Error codes. */
#define OCB_OK 1 // Operation succeeded successfully.
#define OCB_TAG_OK 2 // Tag verification succeeded successfully.

#define OCB_ERR_INVALID_CTX -1 // NULL or invalid ctx parameter.
#define OCB_ERR_INVALID_MODE -2 // Invalid crypt mode supplied. (Must be either OCB_ENC or OCB_DEC)
#define OCB_ERR_INVALID_KEY -3 // NULL or invalid key parameter.
#define OCB_ERR_INVALID_KEY_BITS -4 // Invalid number of key bits supplied. (can be 128, 192 or 256 only)
#define OCB_ERR_INVALID_TAG_PARAM -5 // NULL tag buffer supplied.
#define OCB_ERR_INVALID_AD_PARAM -6 // NULL additional data buffer or 0 AD len parameter supplied.
#define OCB_ERR_CRYPT_SETKEY_FAIL -7 // The underlying block cipher's set key operation failed.
#define OCB_ERR_CRYPT_FAIL -8 // The underlying block cipher's crypt operation failed.
#define OCB_ERR_NONCE_FAIL -9 // The nonce generation failed.
#define OCB_ERR_AAD_HASH_FAIL -10 // AAD Hash operation failed.
#define OCB_ERR_TAG_FAIL -11 // Verification failed of the supplied tag.
#define OCB_ERR_ALLOC_FAIL -12 // Memory allocation failed.
#define OCB_ERR_NO_OUT_BUF -13 // No output parameter supplied.
#define OCB_ERR_NO_NONCE -14 // No nonce supplied.
#define OCB_ERR_NO_IN_BUF -15 // No input parameter supplied.

typedef struct
{
   /*mbedtls_aes_context aes;
   mbedtls_aes_context aes_dec;*/
   blockcipher_ctx blockcipher_enc;
   blockcipher_ctx blockcipher_dec;
   uint8_t L_asterisk[16];
   uint8_t L_dollar[16];
}ocb_ctx;

void ocb_init(ocb_ctx* ctx);
void ocb_free(ocb_ctx* ctx);

int ocb_set_key(ocb_ctx* ctx, const uint8_t* key, const int keybits);
int ocb_aad(ocb_ctx* ctx, uint8_t* tag, const uint8_t* ad, const size_t ad_len, uint8_t* L_off);

int ocb_encrypt(ocb_ctx* ctx, uint8_t* ciphertext, const uint8_t* nonce, const size_t nlen, const uint8_t* plaintext, const size_t plen, const uint8_t* ad, const size_t ad_len);
int ocb_decrypt(ocb_ctx* ctx, uint8_t* plaintext, const uint8_t* nonce, const size_t nlen, const uint8_t* ciphertext, const size_t clen, const uint8_t* ad, const size_t ad_len);

#endif H_OCB_H