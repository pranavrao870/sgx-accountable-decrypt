Enclave

struct state_t {
	// RSA structs 
	RSA 		*decrypt_key;
	// Pritable PEM keys

	// Root hash context
	uint8_t 	*root_hash;
	//Serialized state for suspend/restore
	uint8_t 	*serialized_state;
	//sgx_mono_counter seal_counter;

};

public sgx_status_t t_set_dec_key(          [in, size=RSA_KEY_SIZE] RSA *decrypt_key );

public sgx_status_t t_get_

public sgx_status_t t_decrypt_record(       [in, size=proof_len] Proof *proof,
                                            [in] size_t proof_len,
                                            [in, size=RSA_BLOCK_SIZE]  uint8_t *encrypted_record, 
                                            [out, size=RSA_BLOCK_SIZE] uint8_t *decrypted_record, 
                                            [out, count=1]   size_t *decrypted_len);

App

Device


Log
