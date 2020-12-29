#include "ocb.h"

static void xor16(uint8_t* out, uint8_t* in1, uint8_t* in2)
{
   for (size_t i = 0; i < 16; i++)
       out[i] = in1[i] ^ in2[i];
}

static void ocb_double(uint8_t out[16], uint8_t in[16])
{
    int bit;
    uint8_t t0, t1 = 0;
    
    memcpy(out, in, 16);
    bit = out[0] >> 7;
    t1 = 0;
    
    for (size_t i = 16; i-- > 0;)
    {
        t0 = out[i] >> 7;
        out[i] <<= 1;
        out[i] |= t1;
        t1 = t0;
    }
    
    out[15] ^= (0x87 & -bit);
} 

static void ocb_lshift(uint8_t* in, size_t len, int shift)
{
    size_t t0, t1 = 1;
    
    for (size_t i = len; i-- > 0;)
    {
        t0 = in[i] >> (8 - shift);
        in[i] <<= shift;
        in[i] |= t1;
        t1 = t0;
    }
}

static size_t ntz(size_t n)
{
    size_t count = 0;
    do
    {
        if (n & 1)
           break;
        
        count++;
    } while (n >>= 2);
    
    return count;
}


static void secure_zeroize(uint8_t* buf, size_t len)
{
    volatile uint8_t* p = buf;

    for (size_t i = 0; i < len; i++)
        *p = 0;
}

static uint8_t* offsets_alloc(size_t n)
{
   uint8_t* offsets;
   
   /* Note: we use + 1 to allocate an additional L offset for the final partial block. */
   
   offsets = calloc(n + 1, 16);
   return offsets;
}

static void offsets_free(uint8_t* offsets, size_t n)
{
   if (offsets == NULL)
       return;
   
   /* Note: we use + 1 to allocate an additional L offset for the final partial block. */
   
   secure_zeroize(offsets, (n + 1) * 16);
   free(offsets);
}


static int timesafe_cmp_tag(uint8_t* in1, uint8_t* in2, size_t len)
{
    uint8_t result;
    
    result = 0;
    
    for (size_t i = 0; i < len; i++)
        result |= in1[i] ^ in2[i];
    
    if (result == 0)
        return OCB_TAG_OK;
    
    return OCB_ERR_TAG_FAIL;
}

static void precompute_L(uint8_t* L_offsets, ocb_ctx* ctx, int blocks)
{
   ocb_double(L_offsets, ctx->L_dollar);
   
   for (int i = 1; i < blocks; i++)
   	   ocb_double(L_offsets + 16*i, L_offsets + (i - 1) * 16);
}

static int get_offset_from_nonce(uint8_t* offset, ocb_ctx* ctx, const uint8_t* nonce, const size_t nlen)
{
    /* Setup the nonce: taglen (7 bits) | padding of 0's (120 - nlen)| 1 bit | nonce. */
    
    uint8_t full_nonce[16] = { 0 };
    uint8_t stretch[24] = { 0 };
    int bottom, shift, off;
    
    full_nonce[0] = TAGLEN_BITS & 7 << 1; /* Modulo 128 and shift by 1, we make the first 7 bits the TAGLEN. */
    full_nonce[15 - nlen] |= 1;
    memcpy(full_nonce + 1 + (15 - nlen), nonce, nlen);
    
    bottom = full_nonce[15] & 6; /* Modulo 64, we want the last 6 bits. */
    shift = bottom & 4; /* Modulo 8, we align on byte boundary. */
    off = bottom >> 4; /* Division by 8, offset to where the byte we aligned begins. */
    
    full_nonce[15] &= 0xC0;
    
    /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, full_nonce, stretch) != 0)
        return OCB_ERR_CRYPT_FAIL;*/

    if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, stretch, full_nonce) == BLOCKCIPHER_ERR)
        return OCB_ERR_CRYPT_FAIL;
    
    for (size_t i = 0; i < 8; i++)
        stretch[i + 16] = stretch[i] ^ stretch[i + 1];
    
    ocb_lshift(stretch, 24, shift);
    memcpy(offset, stretch + off, 16);
    
    return OCB_OK;
}

static int ocb_process_block(uint8_t* block, int mode, ocb_ctx* ctx, uint8_t* offset)
{
   //int internal_mode;
   //mbedtls_aes_context* aes;
   blockcipher_ctx* cipher_ctx;
   
   if (mode == BLOCKCIPHER_ENC)
   {
   	  //internal_mode = MBEDTLS_AES_ENCRYPT;
   	  cipher_ctx = &ctx->blockcipher_enc;
   }
   else
   {
   	 // internal_mode = MBEDTLS_AES_DECRYPT;
       cipher_ctx = &ctx->blockcipher_dec;
   }
   
   xor16(block, block, offset);
   
   /*if (mbedtls_aes_crypt_ecb(aes, internal_mode, block, block) != 0)
   	   return OCB_ERR_CRYPT_FAIL;*/

    if (blockcipher_crypt_block(cipher_ctx, mode, block, block) == BLOCKCIPHER_ERR)
        return OCB_ERR_CRYPT_FAIL;
   
   xor16(block, block, offset);
   
   return OCB_OK;
}


void ocb_init(ocb_ctx* ctx)
{
   if (ctx == NULL)
   	   return;
   
   memset(ctx, 0, sizeof(ocb_ctx));
   /*mbedtls_aes_init(&ctx->aes);
   mbedtls_aes_init(&ctx->aes_dec);*/
   blockcipher_init(&ctx->blockcipher_enc);
   blockcipher_init(&ctx->blockcipher_dec);
}

void ocb_free(ocb_ctx* ctx)
{
    if (ctx == NULL)
        return;
    
    /*mbedtls_aes_free(&ctx->aes);
    mbedtls_aes_free(&ctx->aes_dec);*/
    blockcipher_free(&ctx->blockcipher_enc);
    blockcipher_free(&ctx->blockcipher_dec);
    secure_zeroize(ctx->L_asterisk, 16);
    secure_zeroize(ctx->L_dollar, 16);
}


int ocb_set_key(ocb_ctx* ctx, const uint8_t* key, const int keybits)
{
   if (ctx == NULL)
   	   return OCB_ERR_INVALID_CTX;
   
   if (key == NULL)
   	   return OCB_ERR_INVALID_KEY;
   
   if (keybits != 128 && keybits != 192 && keybits != 256)
   	   return OCB_ERR_INVALID_KEY_BITS;
   
   /*if (mbedtls_aes_setkey_enc(&ctx->aes, key, keybits) != 0)
   	   return OCB_ERR_CRYPT_SETKEY_FAIL;
   
   if (mbedtls_aes_setkey_dec(&ctx->aes_dec, key, keybits) != 0)
   	   return OCB_ERR_CRYPT_SETKEY_FAIL;*/

   if (blockcipher_set_key(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, key, keybits) == BLOCKCIPHER_ERR)
       return OCB_ERR_CRYPT_SETKEY_FAIL;

   if (blockcipher_set_key(&ctx->blockcipher_dec, BLOCKCIPHER_DEC, key, keybits) == BLOCKCIPHER_ERR)
       return OCB_ERR_CRYPT_SETKEY_FAIL;
   
   memset(ctx->L_asterisk, 0, 16);
   
   /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, ctx->L_asterisk, ctx->L_asterisk) != 0)
   	   return OCB_ERR_CRYPT_FAIL;*/

   if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, ctx->L_asterisk, ctx->L_asterisk) == BLOCKCIPHER_ERR)
       return OCB_ERR_CRYPT_FAIL;
   
   ocb_double(ctx->L_dollar, ctx->L_asterisk);
   
   return OCB_OK;
}

int ocb_aad(ocb_ctx* ctx, uint8_t* tag, const uint8_t* ad, const size_t ad_len, uint8_t* L_off)
{
   if (ctx == NULL)
   	   return OCB_ERR_INVALID_CTX;
   
   if (tag == NULL)
   	   return OCB_ERR_INVALID_TAG_PARAM;
   
   if (ad == NULL || ad_len == 0)
       return OCB_ERR_INVALID_AD_PARAM;
   
   int off_cond;
   size_t blocks, partial;
   uint8_t* L_offsets;
   uint8_t sum[16] = { 0 };
   uint8_t offset[16] = { 0 };
   uint8_t final_offset[16] = { 0 };
   uint8_t padding[16] = { 0 };
   uint8_t tmp_block[16] = { 0 };
   
   blocks = ad_len >> 4; /* Division by 16, number of full 16-byte blocks. */
   partial = ad_len % 16; /* The size of the last partial 16-byte block. */
   
   off_cond = (L_off == NULL);
   
   /* Allocate L_offsets and precompute the L_i's. */
   if (off_cond)
   {
   	  L_offsets = offsets_alloc(blocks);
   	  
   	  if (L_offsets == NULL)
   	  	  return OCB_ERR_ALLOC_FAIL;
   }
   else
   {
   	  L_offsets = L_off;
   }
   
   precompute_L(L_offsets, ctx, blocks);
   
   /* Auth full blocks. */
   for (size_t i = 1; i <= blocks; i++)
   {
   	  xor16(offset, offset, L_offsets + 16*ntz(i));
   	  
   	  memcpy(tmp_block, ad + (i - 1) * 16, 16);
   	  
   	  xor16(tmp_block, tmp_block, offset);
   	  
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, tmp_block, tmp_block) != 0)
   	  {
   	  	  if (off_cond) offsets_free(L_offsets, blocks);
   	  	  return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, tmp_block, tmp_block) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
   	  
   	  xor16(sum, sum, tmp_block);
   }
   
   if (partial)
   {
   	  xor16(final_offset, offset, ctx->L_asterisk);
   	  
   	  memcpy(padding, ad + (blocks * 16), partial);
   	  padding[partial] |= 0x80;
   	  
   	  xor16(padding, padding, final_offset);
   	  
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, padding, padding) != 0)
   	  {
   	  	  if (off_cond) offsets_free(L_offsets, blocks);
   	  	  return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, padding, padding) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
   	  
   	  xor16(sum, sum, padding);
   }
   
   /* tag must be atleast TAGLEN. */
   memcpy(tag, sum, TAGLEN);
   if (off_cond) offsets_free(L_offsets, blocks);
   return OCB_OK;
}


int ocb_encrypt(ocb_ctx* ctx, uint8_t* ciphertext, const uint8_t* nonce, const size_t nlen, const uint8_t* plaintext, const size_t plen, const uint8_t* ad, const size_t ad_len)
{
   if (ctx == NULL)
       return OCB_ERR_INVALID_CTX;
   
   if (ciphertext == NULL)
       return OCB_ERR_NO_OUT_BUF;
   
   if (nonce == NULL || nlen == 0)
       return OCB_ERR_NO_NONCE;
   
   if (plaintext == NULL || plen == 0)
       return OCB_ERR_NO_IN_BUF;
   
   size_t blocks, partial;
   uint8_t* L_offsets;
   uint8_t offset[16] = { 0 };
   uint8_t final_offset[16] = { 0 };
   uint8_t padding[16] = {0};
   uint8_t checksum[16] = { 0 };
   uint8_t final_checksum[16] = { 0 };
   uint8_t aad_tag[16] = { 0 };
   
   blocks = plen >> 4; /* Division by 16, number of full 16-byte blocks. */
   partial = plen % 16; /* The size of the last partial 16-byte block. */
   
   /* Allocate L_offsets and precompute the L_i's. */
   L_offsets = offsets_alloc(blocks);
   
   if (L_offsets == NULL)
   	   return OCB_ERR_ALLOC_FAIL;
   
   precompute_L(L_offsets, ctx, blocks);
   
   if (get_offset_from_nonce(offset, ctx, nonce, nlen) != OCB_OK)
   {
   	  offsets_free(L_offsets, blocks);
   	  return OCB_ERR_NONCE_FAIL;
   }
   
   /* Encrypt full blocks. */
   for (size_t i = 1; i <= blocks; i++)
   {
   	  xor16(offset, offset, L_offsets + 16*ntz(i));
      
   	  memcpy(ciphertext, plaintext + (i - 1)*16, 16);
   	  
   	  xor16(checksum, checksum, ciphertext);
      
   	  if (ocb_process_block(ciphertext, OCB_ENC, ctx, offset) != OCB_OK)
   	  {
   	     offsets_free(L_offsets, blocks);
   	     return OCB_ERR_CRYPT_FAIL;
   	  }
   }
   
   /* Handle any partial final blocks. */
   if (partial)
   {
   	  xor16(final_offset, offset, ctx->L_asterisk);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_offset, padding) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/

      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, padding, final_offset) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
      
   	  for(size_t i = 0; i < partial; i++)
   	  	  padding[i] ^= (plaintext + blocks * 16)[i];
      
   	  memcpy(ciphertext + blocks * 16, padding, partial);
      
   	  memcpy(final_checksum, plaintext + blocks * 16, partial);
   	  final_checksum[partial] |= 0x80;
   	  xor16(final_checksum, final_checksum, checksum);
      
   	  xor16(final_checksum, final_checksum, final_offset);
   	  xor16(final_checksum, final_checksum, ctx->L_dollar);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_checksum, final_checksum) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, final_checksum, final_checksum) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }

   }
   else
   {
   	  xor16(final_checksum, checksum, offset);
   	  xor16(final_checksum, final_checksum, ctx->L_dollar);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_checksum, final_checksum) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, final_checksum, final_checksum) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
   }
   
   /* final_checksum holds the tag, we have to XOR it with HASH(K, A), in our case this is ocb_aad which gives us the additional data hash. */
   
   if (ad != NULL && ad_len != 0 && ocb_aad(ctx, aad_tag, ad, ad_len, L_offsets) != OCB_OK)
   {
   	 offsets_free(L_offsets, blocks);
   	 return OCB_ERR_AAD_HASH_FAIL;
   }
   
   xor16(final_checksum, final_checksum, aad_tag);
   
   /* We have to ensure ciphertext buffer can hold atleast plen + TAGLEN, so we could copy to ciphertext + plen safely. */
   memcpy(ciphertext + plen, final_checksum, TAGLEN);
   offsets_free(L_offsets, blocks);
   return OCB_OK;
}

int ocb_decrypt(ocb_ctx* ctx, uint8_t* plaintext, const uint8_t* nonce, const size_t nlen, const uint8_t* ciphertext, const size_t clen, const uint8_t* ad, const size_t ad_len)
{
   if (ctx == NULL)
       return OCB_ERR_INVALID_CTX;
   
   if (plaintext == NULL)
       return OCB_ERR_NO_OUT_BUF;
   
   if (nonce == NULL || nlen == 0)
       return OCB_ERR_NO_NONCE;
   
   if (ciphertext == NULL || clen == 0)
       return OCB_ERR_NO_IN_BUF;

   size_t blocks, partial;
   uint8_t* L_offsets;
   uint8_t offset[16] = { 0 };
   uint8_t final_offset[16] = { 0 };
   uint8_t padding[16] = { 0 };
   uint8_t checksum[16] = { 0 };
   uint8_t final_checksum[16] = { 0 };
   uint8_t ctag[16] = { 0 };
   uint8_t aad_tag[16] = { 0 };
   
   blocks = (clen - TAGLEN) >> 4; /* Division by 16, number of full 16-byte blocks. */
   partial = (clen - TAGLEN) % 16; /* The size of the last partial 16-byte block. */
   
   /* Allocate L_offsets and precompute the L_i's. */
   L_offsets = offsets_alloc(blocks);
   
   if (L_offsets == NULL)
   	   return OCB_ERR_ALLOC_FAIL;
   
   precompute_L(L_offsets, ctx, blocks);
   
   if (get_offset_from_nonce(offset, ctx, nonce, nlen) != OCB_OK)
   {
   	  offsets_free(L_offsets, blocks);
   	  return OCB_ERR_NONCE_FAIL;
   }
   
   /* Decrypt full blocks. */
   for (size_t i = 1; i <= blocks; i++)
   {
   	  xor16(offset, offset, L_offsets + 16*ntz(i));
      
   	  memcpy(plaintext, ciphertext + (i - 1) * 16, 16);
      
   	  if (ocb_process_block(plaintext, OCB_DEC, ctx, offset) != OCB_OK)
   	  	  return OCB_ERR_CRYPT_FAIL;
      
   	  xor16(checksum, checksum, plaintext);
   }
   
   /* Handle any partial final blocks. */
   if (partial)
   {
   	  xor16(final_offset, offset, ctx->L_asterisk);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_offset, padding) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, padding, final_offset) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
      
   	  for (size_t i = 0; i < partial; i++)
   	  	   padding[i] ^= (ciphertext + blocks * 16)[i];
      
   	  memcpy(plaintext + blocks * 16, padding, partial);
      
   	  memcpy(final_checksum, plaintext + blocks * 16, partial);
   	  final_checksum[partial] |= 0x80;
   	  xor16(final_checksum, final_checksum, checksum);
      
   	  xor16(final_checksum, final_checksum, final_offset);
   	  xor16(final_checksum, final_checksum, ctx->L_dollar);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_checksum, final_checksum) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, final_checksum, final_checksum) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
   }
   else
   {
   	  xor16(final_checksum, checksum, offset);
   	  xor16(final_checksum, final_checksum, ctx->L_dollar);
      
   	  /*if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, final_checksum, final_checksum) != 0)
   	  {
   	  	 offsets_free(L_offsets, blocks);
   	  	 return OCB_ERR_CRYPT_FAIL;
   	  }*/
      if (blockcipher_crypt_block(&ctx->blockcipher_enc, BLOCKCIPHER_ENC, final_checksum, final_checksum) == BLOCKCIPHER_ERR)
      {
          offsets_free(L_offsets, blocks);
          return OCB_ERR_CRYPT_FAIL;
      }
   }
   
   /* final_checksum holds the tag, we have to XOR it with HASH(K, A), in our case this is ocb_aad which gives us the additional data hash. */
   
   if (ad != NULL && ad_len != 0 && ocb_aad(ctx, aad_tag, ad, ad_len, L_offsets) != OCB_OK)
   {
   	  offsets_free(L_offsets, blocks);
   	  return OCB_ERR_AAD_HASH_FAIL;
   }
   
   xor16(final_checksum, final_checksum, aad_tag);
   
   memcpy(ctag, ciphertext + blocks*16 + partial, TAGLEN);
   
   /* Verify the tag we got is correct. */
   if (timesafe_cmp_tag(ctag, final_checksum, TAGLEN) != OCB_TAG_OK)
       return OCB_ERR_TAG_FAIL;
   
   offsets_free(L_offsets, blocks);
   return OCB_OK;
}