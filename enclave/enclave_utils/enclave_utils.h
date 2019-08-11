#ifndef ENCLAVE_UTILS_H_   /* Include guard */
#define ENCLAVE_UTILS_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../Enclave.h"

// Header counts and locations in a serialized state array
#define HEADER_COUNT 3
enum HEADER_SIZE_OFFSETS {
    DECRYPT_KEY_HEADER = 0,
    SIGNING_KEY_HEADER,
    ROOT_HASH_HEADER
};


// Proof verification 
int32_t t_verify_presence(char* proof, int prooflen, int* dir,char* root_hash);

int32_t t_verify_extension(char* proof, int prooflen, int* dir, char* root_hash, char *new_hash);

#endif