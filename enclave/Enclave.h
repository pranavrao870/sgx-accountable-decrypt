#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/rsa.h>


#define RSA_KEY_SIZE 3072 // Make sure size of [int/out] buffers in EDL header = RSA_KEY_SIZE/8 .
#define RSA_KEY_ENTROPY_LEN 40 // 320-bits of randomness used to seed the OpenSSL CPRNG

struct state_t {
	// RSA structs 
	RSA 		*decrypt_key;
	RSA 		*signing_key;
	// Pritable PEM keys
	uint8_t 	*encrypt_pem;
	uint8_t 	*verify_pem;

	// Root hash context
	char* 	root_hash;
	//sgx_mono_counter seal_counter;

};


#define TEST_CHECK(status)	\
{	\
	if (status != SGX_SUCCESS) {	\
		printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);	\
		abort();	\
	}	\
}

#if defined(__cplusplus)
extern "C" {
#endif


void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
