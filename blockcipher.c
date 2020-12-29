/*#include "blockcipher.h"
#include "ocb.h"

static void blockcipher_init(blockcipher_ctx* ctx)
{
	mbedtls_aes_init(ctx);
}

static void blockcipher_free(blockcipher_ctx* ctx)
{
	mbedtls_aes_free(ctx);
}

static int blockcipher_set_key(blockcipher_ctx* ctx, int mode, uint8_t* key, size_t keybits)
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
}*/