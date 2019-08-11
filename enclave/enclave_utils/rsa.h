#ifndef RSA_H_   /* Include guard */
#define RSA_H_


#include <openssl/rsa.h>
#include <stdint.h>



RSA* t_RSA_generate_key(uint32_t keysize, uint8_t *entropy);

RSA* createRSA(uint8_t *key, int publ);

void t_free_rsa_key(RSA *keypair);

uint8_t* t_export_pub_key(RSA* keypair);

uint8_t* t_export_priv_key(RSA *keypair);

int32_t t_rsa_decrypt(RSA *keypair, uint8_t *encrypted, uint8_t *decrypted);

int32_t t_rsa_encrypt(RSA *keypair, int data_len, uint8_t *decrypted, uint8_t *encrypted);

#endif