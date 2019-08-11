#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdint.h>

#include "rsa.h"
#include "tSgxSSL_api.h"
#include "../Enclave.h"

// TODO comments and proper error cheking and return vals


RSA* t_RSA_generate_key(uint32_t keysize, uint8_t *entropy)
{
    BIGNUM *bn;
    RSA *keypair;

    RAND_seed(entropy, RSA_KEY_ENTROPY_LEN);

	bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return NULL;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return NULL;
	}
	
	keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return NULL;
	}

	ret = RSA_generate_key_ex(keypair, keysize, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return NULL;
	}

	return keypair;
}

RSA *createRSA(uint8_t *key, int publ){
	RSA *rsa = NULL;
	BIO *keybio = NULL;
	keybio = BIO_new_mem_buf(key, -1);
	if(publ){
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else{
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
	return rsa;
}

void t_free_rsa_key(RSA *keypair)
{
    if(keypair != NULL)
        RSA_free(keypair);
}

uint8_t* t_export_pub_key(RSA* keypair)
{

    // To get the C-string PEM form:
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pub_len = BIO_pending(pub);
    uint8_t *pub_key = (uint8_t*)malloc(pub_len + 1);

    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';

    return pub_key;
}

uint8_t* t_export_priv_key(RSA *keypair)
{
    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	if(ERR_get_error() != 0){
		printf("PEM_write_bio_RSAPrivateKey failure: %ld\n", ERR_get_error());
		return NULL;
	}

    size_t pri_len = BIO_pending(pri);
	if(ERR_get_error() != 0){
		printf("BIO_pending failure: %ld\n", ERR_get_error());
		return NULL;
	}

    uint8_t *pri_key = (uint8_t *)malloc(pri_len + 1);
	if(!pri_key){
		return NULL;
	}

    BIO_read(pri, pri_key, pri_len);
    pri_key[pri_len] = '\0';
	if(ERR_get_error() != 0){
		printf("BIO_read failure: %ld\n", ERR_get_error());
		return NULL;
	}

    return pri_key;
}

int32_t t_rsa_decrypt(RSA *keypair, uint8_t *encrypted, uint8_t *decrypted){
    int32_t ret =  RSA_private_decrypt(RSA_KEY_SIZE/8, encrypted, decrypted, keypair, RSA_PKCS1_OAEP_PADDING);
    if(ERR_get_error()){
        printf("RSA_private_decrypt failure: %ld ret:%d\n", ERR_get_error(), ret);
        return ret;
    }
    return ret;
}

int32_t t_rsa_encrypt(RSA *keypair, int data_len, uint8_t *decrypted, uint8_t *encrypted){
	int32_t ret = RSA_public_encrypt(data_len, decrypted, encrypted, keypair, RSA_PKCS1_OAEP_PADDING);
	if(ERR_get_error()){
		printf("RSA_public_encrypt failure: %ld ret:%d\n", ERR_get_error(), ret);
	}
	return ret;
}