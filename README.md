# Offset Codebook (OCB) AEAD Encryption Mode of Operation
Portable C Implementation of Offset Codebook (OCB) AEAD Encryption Mode of Operation by Phillip Rogaway.

It uses a software implementation of AES from mbedTLS located inside the cipher folder and implemented inside the blockcipher.h wrapper.

To implement your own underlying block cipher, simply overwrite the four functions inside blockcipher.h
