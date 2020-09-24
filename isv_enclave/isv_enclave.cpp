
#include "isv_enclave_t.h" //trusted auto-generated header for wraper function
//#include"sgx_key_exchange.h"
#include "sgx_tkey_exchange.h" // contains sgx_ra_context_t
//#include"sgx_tae_service.h"//required for sgx_close_pse_session
#include "sgx_tcrypto.h" //required for sgx_ec256_public_t
#include "string.h"
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif


// This is the public EC key of the SP. 
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

uint8_t g_secret[8] = {0};



#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
	uint8_t counter[4];
	sgx_ec256_dh_shared_t shared_secret;
	uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
	const sgx_ec256_dh_shared_t *p_shared_key,
	uint8_t key_id,
	sgx_ec_key_128bit_t *first_derived_key,
	sgx_ec_key_128bit_t *second_derived_key)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	hash_buffer_t hash_buffer;
	sgx_sha_state_handle_t sha_context;
	sgx_sha256_hash_t key_material;

	memset(&hash_buffer, 0, sizeof(hash_buffer_t));
	/* counter in big endian  */
	hash_buffer.counter[3] = key_id;

	/*convert from little endian to big endian */
	for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
	{
		hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s) - 1 - i];
	}

	sgx_ret = sgx_sha256_init(&sha_context);
	if (sgx_ret != SGX_SUCCESS)
	{
		return false;
	}
	sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
	if (sgx_ret != SGX_SUCCESS)
	{
		sgx_sha256_close(sha_context);
		return false;
	}
	sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
	if (sgx_ret != SGX_SUCCESS)
	{
		sgx_sha256_close(sha_context);
		return false;
	}
	sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
	if (sgx_ret != SGX_SUCCESS)
	{
		sgx_sha256_close(sha_context);
		return false;
	}
	sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
	if (sgx_ret != SGX_SUCCESS)
	{
		sgx_sha256_close(sha_context);
		return false;
	}
	sgx_ret = sgx_sha256_close(sha_context);

	static_assert(sizeof(sgx_ec_key_128bit_t) * 2 == sizeof(sgx_sha256_hash_t), "structure size mismatch.");
	memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
	memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

	// memset here can be optimized away by compiler, so please use memset_s on
	// windows for production code and similar functions on other OSes.
	memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

	return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
	DERIVE_KEY_SMK_SK = 0,
	DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
	uint16_t kdf_id,
	sgx_ec_key_128bit_t* smk_key,
	sgx_ec_key_128bit_t* sk_key,
	sgx_ec_key_128bit_t* mk_key,
	sgx_ec_key_128bit_t* vk_key)
{
	bool derive_ret = false;

	if (NULL == shared_key)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (ISV_KDF_ID != kdf_id)
	{
		return SGX_ERROR_KDF_MISMATCH;
	}

	derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,smk_key, sk_key);
	if (derive_ret != true)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,mk_key, vk_key);
	if (derive_ret != true)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif





sgx_status_t enclave_init_ra( int b_pse,  sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse) //STEP 2: If b_pse is true....
    {
	
            ret = sgx_create_pse_session(); //to establish a session with PSE.
      
    }



//#ifdef SUPPLIED_KEY_DERIVATION
//    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
//#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context); // STEP 3 : Code in the enclave calls sgx_ra_init(), passing in the SP PK ..
//#endif
    if(b_pse)
    {
        sgx_close_pse_session(); //STEP 4 :Close PSE session
        return ret;
    }
    return ret;
}



//As defined in .edl in pdf
sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context)
{
	sgx_status_t ret;
	ret = sgx_ra_close(context);
	return ret;
}



// Verify the mac sent in att_result_msg from the SP using the// MK key. //  context The trusted KE library key context.
//  p_message Pointer to the message used to produce MAC//  message_size Size in bytes of the message.
//  p_mac Pointer to the MAC to compare to.//  mac_size Size in bytes of the MAC
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* p_message, size_t message_size, uint8_t* p_mac, size_t mac_size)
{
	sgx_status_t ret;
	sgx_ec_key_128bit_t mk_key;

	if (mac_size != sizeof(sgx_mac_t))
	{
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}


	do {
		uint8_t mac[SGX_CMAC_MAC_SIZE] = { 0 };//16 defined in sgx_tcrypto

		 sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
		 if (SGX_SUCCESS != ret)//dorkar nai
		 {
			 break;
		 }
		 sgx_rijndael128_cmac_msg(&mk_key, p_message, (uint32_t)message_size, &mac);
		 if (SGX_SUCCESS != ret)//dorkar nai
		 {
			 break;
		 }
	

	} while (0);

	return ret;
}










// Closes the tKE key context used during the SIGMA key
// exchange. @param context The trusted KE library key context. @return Return value from the key context close API

//As defined in .edl in pdf
/*sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}*/


// Generate a secret information for the SP encrypted with SK.
// context The trusted KE library key context.
//p_secret Message containing the secret.
//secret_size Size in bytes of the secret message.
//  p_gcm_mac The pointer the the AESGCM MAC for the  message.


sgx_status_t put_secret_data(	sgx_ra_context_t context,	uint8_t *p_secret,	uint32_t secret_size,	uint8_t *p_gcm_mac)
{
	sgx_status_t ret = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;

	do {
		if (secret_size != 8)
		{
			ret = SGX_ERROR_INVALID_PARAMETER;
			break;
		}

		ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
		if (SGX_SUCCESS != ret)
		{
			break;
		}

		uint8_t aes_gcm_iv[12] = { 0 };
		ret = sgx_rijndael128GCM_decrypt(&sk_key,p_secret,secret_size,	&g_secret[0],	&aes_gcm_iv[0],	12,	NULL,0,	(const sgx_aes_gcm_128bit_tag_t *)	(p_gcm_mac));

		uint32_t i;
		bool secret_match = true;
		for (i = 0; i<secret_size; i++)
		{
			if (g_secret[i] != i)
			{
				secret_match = false;
			}
		}

		if (!secret_match)
		{
			ret = SGX_ERROR_UNEXPECTED;
		}

		// Once the server has the shared secret, it should be sealed to
		// persistent storage for future use. This will prevents having to
		// perform remote attestation until the secret goes stale. Once the
		// enclave is created again, the secret can be unsealed.
	} while (0);
	return ret;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif