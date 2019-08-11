/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <stack>
#include <vector>
#include <utility>
#include <string>
#include <iostream>
#include <queue>
using namespace std;

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>

#include "TestApp.h"

#include "Enclave_u.h"

#include "app_utils/json_utils.h"

extern "C" {
    #include "app_utils/rsa.h"
}

using namespace std;

string sha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	stringstream ss;
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}
	return ss.str();
}

class Hash{
private:
	string hashvalue;
public:
	Hash(string s){
		hashvalue = sha256(s);
	}
	Hash(){
		hashvalue = "";
	}

	string getHash(){
		return hashvalue;
	}
	void setHash(string val){
		hashvalue = val;
	}
	Hash* concat(Hash* b){
		Hash * h = new Hash(b->getHash() + this->getHash());
		return h;
	}

};

class Node{
private:
	Hash * hash;
	
public:
	Node * left;
	Node * right;
	Node(Hash * hash1){
		hash = new Hash();
        hash->setHash(hash1->getHash());
		left = NULL;
		right= NULL;
	}

	Hash * getHash(){
		return hash;
	}

	void setHash(Hash *val){
		hash = new Hash();
        hash->setHash(val->getHash());
	}
};

class log_tree{
private:
	int count;
	Hash * rootHash;
	
	Node * inserthelper(Node * node, Hash * value, int l){
		double logl = log2(l);
		// cout << logl << " " << l << endl;

		if(logl == (int)(logl)){
			Node * leaf = new Node(value);
			Hash * newhash = value -> concat((node->getHash()));
			Node * internal = new Node(newhash);
			internal ->left = node;
			internal ->right = leaf;
			return internal;
		}
		else{
			// if(node == NULL){
			// 	return NULL;
			// }
			int left = pow(2, (int)logl);
			Node * ret = inserthelper(node->right, value, l - left);
			// if(ret == NULL || node->left == NULL)
			// 	return node;
			Hash * newhash = ret->getHash() -> concat(node->left->getHash());
			node -> setHash(newhash);
			node -> right = ret;
			return node;
		}
	}

public:
	Node * root;
	log_tree(){
		count = 0;
		root = NULL;
		
	}

    void print(){
        if(root == NULL)
        return;
        queue <Node *> bfs;
        bfs.push(root);
        while(!bfs.empty()){
            Node * n = bfs.front();
            cout << n->getHash()->getHash() << endl;
            if(n->left != NULL){
                bfs.push(n->left);
                bfs.push(n->right);
            }
            bfs.pop();
        }

    }

	pair <vector<string>, vector <int> > getep(Hash * h, Node * root){

		stack <Node *> parent;
		vector <int> dirs;
		int check = 0;

		parent.push(root);
		Node * temp = NULL;
		while(!parent.empty()){
			Node * top = parent.top();
			if(h->getHash() == top->getHash()->getHash()){
				check = 1;
				break;
			}
			else if(top->left == NULL) {parent.pop();temp=top;}
			else if(top->left == temp) {parent.pop();temp=top;}
			else if(top->right == temp) {parent.push(top->left);temp=top;}
			else{
				parent.push(top->right);temp=top;
			}
		}
		vector<string> ans(0);
		cout << "The check is " << check << endl;
        if(check ==0 ) 
			return make_pair(ans, dirs);
		temp = parent.top();
		ans.push_back(temp->getHash()->getHash());
		parent.pop();
		while(!parent.empty()){
			Node * top = parent.top();
			parent.pop();
			if(top->left == temp) {
				ans.push_back(top->right->getHash()->getHash());
				dirs.push_back(1);
			}
			else{
				ans.push_back(top->left->getHash()->getHash());
				dirs.push_back(0);
			}
			temp = top;
		}
		return make_pair(ans, dirs);
	}

	Hash *  getRootHash(){
		return  rootHash;
	}
	void insert_record(Hash * value){

		if(count == 0){
			root = new Node(value);
			rootHash = root -> getHash();
			count++;
			return;
		}
		
		Node * node = inserthelper(root, value, count);
		root = node;
		rootHash = root -> getHash();
		
		count ++;
	}

};

// #define RUN_TESTS

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


void usgx_exit(int reason)
{
	printf("usgx_exit: %d\n", reason);
	exit(reason);
}

char* plain_texts[5] = {"Sriram Yv", "Pranav Rao", "Deep K", "Rishabh R", "Gaurav"};
uint8_t *encrypted_texts;
size_t clen;

void encrypt(uint8_t *enc_key){
    clen = rsa_block_size(enc_key);
    encrypted_texts = (uint8_t*)malloc(5 * (clen+1));
    for(int i = 0; i < 5; i++){
        rsa_encrypt(enc_key, (uint8_t*)plain_texts[i], strlen(plain_texts[i]), &encrypted_texts[i*clen], clen);
        encrypted_texts[i*clen + clen] = '\0';
    }
}

void decrypt(int pos, int correct, log_tree *log){
    sgx_status_t ret;
    string s = string((char*)&encrypted_texts[clen * pos]);
    if(correct == 1){
        log->insert_record(new Hash(s));
    }

    cout <<"Dec req The tree is" << endl;
    log->print();
    pair<vector<string>, vector<int> > proof = log->getep(new Hash(s), log->root);
    vector<string> hashes = proof.first;
    vector<int> dirs = proof.second;

    int* dir_arr = new int[dirs.size()];
    char* hash_arr = new char[65 * hashes.size()];
    char* root_hash_arr = new char[65];
    for(int i = 0; i < dirs.size(); i++){
        dir_arr[i] = dirs[i];
    }
    for(int i = 0; i < hashes.size(); i++){
        strcpy(&hash_arr[65*i], hashes[i].c_str());
        hash_arr[65*i + 64] = '\0';
    }

    // Decrypt the message inside the enclave
    uint8_t *decrypted =  (uint8_t*)malloc(clen);
    size_t decrypted_len = 0;
    strcpy(root_hash_arr, log->getRootHash()->getHash().c_str());
    root_hash_arr[64] = '\0';

    ret = t_decrypt_record(global_eid, NULL, &encrypted_texts[clen * pos], decrypted, &decrypted_len, hash_arr, 65 * hashes.size(), dir_arr, 4 * dirs.size(), root_hash_arr);
    if (ret != SGX_SUCCESS) {
        printf("Call to t_decrypt_record has failed.\n");
    }

    else{
        printf("Decrypted (len=%u):\n%s\n", decrypted_len, decrypted);
    }
    printf("\n\n");

    delete dir_arr;
    delete hash_arr;
    delete root_hash_arr;
    free(decrypted);
}


/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Changing dir to where the executable is.*/
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
    	return 1;

    sgx_status_t ret;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1; 
    
    /* Initialize the enclave state*/
    ret = t_initialize_enclave_state(global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Call to t_initialize_enclave has failed.\n");
        return 1; 
    }

    // Get Public keys
    size_t bufsize = 2000;
    uint8_t *enc_key    = (uint8_t*)malloc(bufsize);
    uint8_t *verif_key  = (uint8_t*)malloc(bufsize);

    ret = t_get_public_keys(global_eid, NULL, enc_key, bufsize, verif_key, bufsize);
    if (ret != SGX_SUCCESS) {
        printf("Call to t_get_public_keys has failed.\n");
        return 1; 
    }


    printf("Encryption key:\n%s\n", enc_key);
    printf("Verification key:\n%s\n", verif_key);

    log_tree log;
    
    // Encrypt a test message using the given encryptpion key
    // size_t plen = 384/8;
    // uint8_t pt[plen] = "256-bit AES key";
    // printf("Plaintext:\n%s\n", &pt[0]);

    encrypt(enc_key);
    int pos, correct;
    while(true){
        cin>>pos>>correct;
        if (pos >= 0 && pos < 5){
            decrypt(pos, correct, &log);
        }
    }

    free(enc_key);
    free(verif_key);
    sgx_destroy_enclave(global_eid);
    return 0;
}
