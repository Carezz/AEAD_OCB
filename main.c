#include<stdio.h>
#include<stdint.h>

#include "aes-ocb.h"

void print_buf(uint8_t* buf, size_t len)
{
   for (size_t i = 0; i < len; i++)
       printf("%02X ", buf[i]);
   
   printf("\n\n");
}

void hex2bin(uint8_t* bytes, const uint8_t* hex_str, const size_t len)
{
	size_t pos = 0;

	for (size_t i = 0; i < len / 2; i++, pos++)
	{
	    uint8_t ch0 = hex_str[i + pos];
	    uint8_t ch1 = hex_str[i + 1 + pos];
	    
	    if (ch0 >= '0' && ch0 <= '9')
	    {
	        ch0 -= '0';
	    }
	    else if (ch0 >= 'a' && ch0 <= 'f')
	    {
	        ch0 -= 'W';
	    } 
	    else if (ch0 >= 'A' && ch0 <= 'F')
	    {
	        ch0 -= '7';
	    }
	    
	    if (ch1 >= '0' && ch1 <= '9')
	    {
	        ch1 -= '0';
	    }
	    else if (ch1 >= 'a' && ch1 <= 'f')
	    {
	        ch1 -= 'W';
	    }
	    else if (ch1 >= 'A' && ch1 <= 'F')
	    {
	        ch1 -= '7';
	    }
	    
	    bytes[i] = ch0 << 4;
	    bytes[i] |= ch1;
	}
}

int cmp_values(uint8_t* val1, uint8_t* val2, size_t len)
{
   size_t result = 0;
   
   for (size_t i = 0; i < len; i++)
       result |= val1[i] ^ val2[i];
   
   return result;
}

#define KEY "000102030405060708090a0b0c0d0e0f"
#define KEY_STR_LEN sizeof(KEY)
#define KEY_LEN KEY_STR_LEN / 2
#define KEY_BITS KEY_LEN * 8

#define NONCE "BBAA99887766554433221104"
#define NONCE_STR_LEN sizeof(NONCE)
#define NONCE_LEN NONCE_STR_LEN / 2

#define AD "000102030405060708090A0B0C0D0E0F"
#define AD_STR_LEN sizeof(AD)
#define AD_LEN AD_STR_LEN / 2

#define PLAINTEXT "000102030405060708090A0B0C0D0E0F"
#define PLAINTEXT_STR_LEN sizeof(PLAINTEXT)
#define PLAINTEXT_LEN PLAINTEXT_STR_LEN / 2

#define EXP_CIPHERTEXT "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"
#define EXP_CIPHERTEXT_STR_LEN sizeof(EXP_CIPHERTEXT)
#define EXP_CIPHERTEXT_LEN EXP_CIPHERTEXT_STR_LEN / 2

#define CIPHERTEXT_LEN PLAINTEXT_LEN + TAGLEN

int main()
{
   ocb_ctx ctx;
   int res;

   uint8_t key[KEY_LEN];
   uint8_t nonce[NONCE_LEN];
   uint8_t ad[AD_LEN];
   
   uint8_t plaintext[PLAINTEXT_LEN];
   uint8_t ciphertext[CIPHERTEXT_LEN];
   uint8_t exp_ciphertext[EXP_CIPHERTEXT_LEN];
   uint8_t decrypted[PLAINTEXT_LEN];
   
   hex2bin(key, KEY, KEY_STR_LEN);
   hex2bin(nonce, NONCE, NONCE_STR_LEN);
   hex2bin(ad, AD, AD_STR_LEN);
   
   hex2bin(plaintext, PLAINTEXT, PLAINTEXT_STR_LEN);
   hex2bin(exp_ciphertext, EXP_CIPHERTEXT, EXP_CIPHERTEXT_STR_LEN);
   
   ocb_init(&ctx);
   res = ocb_set_key(&ctx, key, KEY_BITS);
   
   res = ocb_encrypt(&ctx, ciphertext, nonce, NONCE_LEN, plaintext, PLAINTEXT_LEN, ad, AD_LEN);
   
   int tagres = ocb_decrypt(&ctx, decrypted, nonce, NONCE_LEN, ciphertext, CIPHERTEXT_LEN, ad, AD_LEN);
   
   printf("[*] - Plaintext: ");
   print_buf(plaintext, PLAINTEXT_LEN);
   
   printf("[*] - Ciphertext: ");
   print_buf(ciphertext, CIPHERTEXT_LEN);
   
   printf("[*] - Expected Ciphertext: ");
   print_buf(exp_ciphertext, EXP_CIPHERTEXT_LEN);
   
   printf("[*] - Decrypted Plaintext: ");
   print_buf(decrypted, PLAINTEXT_LEN);
   
   printf("====================================\n");
   printf("[*] - Test Vector: ");
   
   if (cmp_values(ciphertext, exp_ciphertext, CIPHERTEXT_LEN) == 0)
   	printf("PASSED! [****]\n");
   else
   	printf("FAILED! [!!!!]\n");
   
   printf("====================================\n");
   
   int r = getchar();
   ocb_free(&ctx);
   return 0;
}