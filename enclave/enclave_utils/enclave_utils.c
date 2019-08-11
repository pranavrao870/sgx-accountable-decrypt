#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_utils.h"
#include "../Enclave.h"
#include "rsa.h"
#include <openssl/sha.h>

// void sha256(char* str, char* dst)
// {
	// unsigned char hash[SHA256_DIGEST_LENGTH];
	// SHA256_CTX sha256;
	// SHA256_Init(&sha256);
	// SHA256_Update(&sha256, str, strlen(str));
	// SHA256_Final(hash, &sha256);
	// stringstream ss;
	// for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
	// 	ss << hex << setw(2) << setfill('0') << (int)hash[i];
	// }
// }

char hex_arr[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char first_half(char t){
    uint8_t mask = 15*16;
    int j = (t & mask) / 16;
    return hex_arr[j];
}

char second_half(char t){
    uint8_t mask = 15;
    int j = (t & mask);
    return hex_arr[j];
}

void sha256(char *string, char* outputBuffer)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        outputBuffer[2*i] = first_half(hash[i]);
        outputBuffer[2*i+1] = second_half(hash[i]);
    }
    outputBuffer[64] = '\0';
}

int32_t t_verify_presence(char* proof, int prooflen, int* dir,char* root_hash){
    if(prooflen <= 0)
		return 0;
	char * hash_val = (char *) malloc(65);

	strncpy(hash_val, proof, 64);
    hash_val[64] = '\0';
    char * temp = (char *) malloc(129);

	for(int i = 1; i < prooflen; i++){

		proof = proof + 65;
        // printf("%d ", dir[i- 1]);
		if(dir[i - 1]  == 0){
			strncpy(temp, proof, 65);
			strncat(temp, hash_val, 64);
            temp[128] = '\0';
			sha256(temp, hash_val);
		}
		else{
			strncpy(temp, hash_val, 65);
			strncat(temp, proof, 64);
            temp[128] = '\0';
			sha256(temp, hash_val);
		}
	}

	int32_t i = strcmp(hash_val, root_hash);
    printf("HASH VAL %s \n\nROOT %s \n\nPROOF %s \n", hash_val, root_hash, proof);

	free(hash_val);
    free(temp);

	return 1 - i;
}

int32_t t_verify_extension(char* proof, int prooflen, int* dir, char* old_hash, char *new_hash){
    if(t_verify_presence(proof, prooflen, dir, new_hash) == 1){
        if(strcmp(old_hash, "") == 0){
            return 1;
        }
        dir = dir + 1;
        proof = proof + 65;
        int ret =  t_verify_presence(proof, prooflen -1 , dir, old_hash);
        printf("The result of verifi %d\n\n", ret);
        return ret;
    }
    printf("not innnnnnnnn \n");
    return 0;
}