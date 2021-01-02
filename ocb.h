#ifndef H_OCB_H
#define H_OCB_H

#include<string.h>
#include<stdint.h>
#include<stdlib.h>

#include "blockcipher.h"

#define TAGLEN_BITS 128
#define TAGLEN TAGLEN_BITS / 8

#define MAX_MSG_LEN 4096 // Default max message length per call, it is used if max_len parameter is not specified.

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
#define OCB_ERR_PLEN_EXCEEDED -16 // Plaintext length supplied in encrypt has exceeded the max message length specified.
#define OCB_ERR_CLEN_EXCEEDED -17 /* Ciphertext length supplied in decrypt has exceeded the max message length specified 
                                   (WARNING: the TAGLEN tag in ciphertext is excluded from this!). */
#define OCB_ERR_ADLEN_EXCEEDED - 18 /* Additional data length supplied in the hash function (ocb_aad) has exceeded the
                                       max message length specified. */

typedef struct
{
   blockcipher_ctx blockcipher_enc;
   blockcipher_ctx blockcipher_dec;
   
   uint8_t L_asterisk[OCB_BLOCK_SIZE];
   uint8_t L_dollar[OCB_BLOCK_SIZE];

   uint8_t* L_offsets;
   size_t max_len;

}ocb_ctx;

/* OCB context initialization routine.
   Parameters:
   - ocb_ctx: An OCB context.

   Description:
   Initializes and clears the OCB context, making it ready for use.
*/
void ocb_init(ocb_ctx* ctx);

/* OCB context free routine.
   Parameters:
   - ocb_ctx: An OCB context.

   Description:
   Frees and clears the OCB context, making it ready for disposal.
*/
void ocb_free(ocb_ctx* ctx);

/* OCB key setup routine.
   Parameters:
   - ocb_ctx: An OCB context.
   - key: A cryptographic key.
   - keybits: Cryptographic key's length in bits (only 3 possible values: 128, 192, 256).
   - max_len: The maximum message length per single encrypt or decrypt call.

   Description:
   Initializes and setups the underlying block cipher's key.
*/
int ocb_set_key(ocb_ctx* ctx, const uint8_t* key, const int keybits, size_t max_len);

/* OCB authenticated additional data (AAD) hash routine.
   Parameters:
   - ocb_ctx: An OCB context.
   - tag: Output buffer for returning and storing the tag of the AAD.
   - ad: The additional data itself.
   - ad_len: Length of the data in bytes.
   - L_off: A buffer to allocated L_offsets. (Optional, used only internally within encrypt and decrypt routines!)

   WARNING: If you plan to call this routine directly, pass NULL parameter to L_off.

   Description:
   Hashes additional data and produces a tag, thereby authenticating it.

   Notes:
   Use this only if you plan to just authenticate data without encrypting, if you plan to do both, please
   use ocb_encrypt routine instead!
*/
int ocb_aad(ocb_ctx* ctx, uint8_t* tag, const uint8_t* ad, const size_t ad_len);

/* OCB encrypt routine.
   Parameters:
   - ocb_ctx: An OCB context.
   - ciphertext: Output buffer for storing the ciphertext.
   - nonce: Buffer holding the nonce.
   - nlen: Length of the nonce in bytes.
   - plaintext: An input buffer to the plaintext to encrypt.
   - plen: Length of the plaintext in bytes.
   - ad: Additional data to be authenticated, but not encrypted. (Optional)
   - ad_len: Length of the additional data in bytes. (Optional)

   WARNING: Ciphertext MUST BE ATLEAST plen + TAGLEN in size!

   Description:
   Encrypts the plaintext, authenticates the additional data (if any) and returns
   the ciphertext and the TAG at the end of it inside ciphertext.

   Notes:
   Nonce's max length is 15 bytes, while 12 bytes are recommended!
   The nonce can simply be a counter.
*/
int ocb_encrypt(ocb_ctx* ctx, uint8_t* ciphertext, const uint8_t* nonce, const size_t nlen, const uint8_t* plaintext, const size_t plen, const uint8_t* ad, const size_t ad_len);

/* OCB decrypt routine.
   Parameters:
   - ocb_ctx: An OCB context.
   - plaintext: Output buffer for storing the plaintext.
   - nonce: Buffer holding the nonce.
   - nlen: Length of the nonce in bytes.
   - ciphertext: An input buffer to the ciphertext to encrypt.
   - clen: Length of the ciphertext in bytes.
   - ad: Additional data to be authenticated, but not encrypted. (Optional)
   - ad_len: Length of the additional data in bytes. (Optional)

   WARNING: Plaintext MUST BE ATLEAST plen in size!

   Description:
   Decrypts the ciphertext, authenticates the additional data (if any) and returns
   the plaintext inside the plaintext buffer.
*/
int ocb_decrypt(ocb_ctx* ctx, uint8_t* plaintext, const uint8_t* nonce, const size_t nlen, const uint8_t* ciphertext, const size_t clen, const uint8_t* ad, const size_t ad_len);

#endif H_OCB_H