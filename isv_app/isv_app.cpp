
#include <stdio.h>
#include <limits.h>
#include "sgx_urts.h" // Needed to create enclave, do ecall and destroy enclave.
#include "sgx_ukey_exchange.h" // Needed for sgx_ra_get_msg1.
#include "sgx_key_exchange.h" // Needed for sgx_ra_msg1_t
#include "remote_attestation_result.h" // Needed for definition of remote attestation messages.
#include "isv_enclave_u.h"

#include "network_ra.h"// Needed to get service provider's information, ra_samp_request_header_t
#include "sgx_uae_service.h"// Needed to query extended epid group id.
#include "service_provider.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#include "sample_messages.h"


#ifdef _MSC_VER
#define ENCLAVE_PATH "isv_enclave.signed.dll"
#else
#define ENCLAVE_PATH "isv_enclave.signed.so"
#endif
uint8_t* msg1_samples[] = { msg1_sample1, msg1_sample2 };
uint8_t* msg2_samples[] = { msg2_sample1, msg2_sample2 };
uint8_t* msg3_samples[] = { msg3_sample1, msg3_sample2 };
uint8_t* attestation_msg_samples[] = { attestation_msg_sample1, attestation_msg_sample2 };


void PRINT_BYTE_ARRAY(	FILE *file, void *mem, uint32_t len)
{
	if (!mem || !len)
	{
		printf( "zero");
		return;
	}
	uint8_t *array = (uint8_t *)mem;
	printf("%u bytes:\n", len);
	uint32_t i = 0;
	for (i = 0; i < len - 1; i++)
	{
		printf( "0x%x, ", array[i]);
		
	}
	printf( "0x%x ", array[i]);
	
}

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, ra_samp_response_header_t *response)
{
	if (!response)
	{
		printf(" msg not received ");
		return;
	}

	printf("RESPONSE TYPE:   0x%x\n", response->type);
	printf("RESPONSE STATUS: 0x%x 0x%x\n", response->status[0], response->status[1]);
	printf("RESPONSE  SIZE: %u\n", response->size);

	if (response->type == TYPE_RA_MSG2)
	{
		sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

		printf("\nMSG2 gb - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));
		printf("\nMSG2 spid - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));
		printf("\nMSG2 quote_type : %hx\n", p_msg2_body->quote_type);
		printf("\nMSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);
		fprintf(file, "\nMSG2 sign_gb_ga - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga), sizeof(p_msg2_body->sign_gb_ga));
		printf("\nMSG2 mac - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));
		 printf("\nMSG2 sig_rl - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),   p_msg2_body->sig_rl_size);
	}
	else
	{
		printf("\nERROR");
	}
}


#ifdef _MSC_VER
#include <TCHAR.H>
int _tmain(int argc, _TCHAR *argv[])
#else
#define _T(x) x
int main(int argc, char* argv[])
#endif


{
	int ret = 0;//sgx create return
	ra_samp_request_header_t *p_msg0_full = NULL;// ra_samp_request_header_t er pointer er nam
	ra_samp_response_header_t *p_msg0_resp_full = NULL;//require for one of the parameter for ra_network_send_receive
	ra_samp_request_header_t *p_msg1_full = NULL;// ra_samp_request_header_t er pointer er nam
	ra_samp_response_header_t *p_msg2_full = NULL;//last parameter for ra_network_send_receive which is expected to retuen back
	sgx_ra_msg3_t *p_msg3 = NULL;
	sgx_enclave_id_t enclave_id = 0;//sgx create parameter & 2nd paramerter for sgx_ra_get_msg1
	sgx_ra_context_t context = INT_MAX;//sgx_ra_get_msg1 first parameter
	sgx_status_t status = SGX_SUCCESS;//sgx create parameter
	ra_samp_request_header_t* p_msg3_full = NULL;
	ra_samp_response_header_t* p_att_result_msg_full = NULL; //step 13 //..send in msg3
	int32_t verify_index = -1;
	int32_t verification_samples = sizeof(msg1_samples) / sizeof(msg1_samples[0]);

	FILE* OUTPUT = stdout; //FILE *fp;

#define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && verify_index <= verification_samples)
#define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

	

	// Step 6: Preparation for remote attestation by configuring extended epid group id.
	{
		uint32_t extended_epid_group_id = 0;
		ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);// syntax is given in the pdf, tells ISV SP which EEPID Group is used
																	  //define in sgx_uae_service.h
																	  //sgx_get_extended_epid_group_id Function used to get active extended epid group id.
																	  //Currently, the only valid extended Intel® EPID group ID is zero. The server should verify this value is zero. 
																	  //If the Intel® EPID group ID is not zero, the server aborts remote attestation. (pg-124)
		if (ret != SGX_SUCCESS)
		{
			printf("Error at step 6");
		}
		else
		{
			printf(" Step 6:epid successfully get ");
		}

		



		//step 7
		p_msg0_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t) + sizeof(uint32_t));//sizeof msg0 is Uint_32

		p_msg0_full->type = TYPE_RA_MSG0; //typedef structure define for ra_samp_request_header_t. p_msg0_full->type means (*p_msg0_full).name
		p_msg0_full->size = sizeof(uint32_t);//same like above

		*(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;//store epid at the location store by this pointer
		{

			printf( "\nStep 7:MSG0 generated ");

			PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

		}
		// The client send msg0 to the SP.
		// The ISV decides whether to support this extended epid group id.
		printf("\nSending msg0 to service provider via ra_network_send_recieve");

		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/", p_msg0_full, &p_msg0_resp_full);//define in network_ra.cpp and &p_msg0_resp_full =NULL
		if (ret != 0)
		{
			printf("Error in step7");
				}
		printf("\nSent MSG0 ");
	}
	

	{

		// STEP 1 : ISV application creates the ISV enclave.
		// ISV application creates the ISV enclave.
		int launch_token_update = 0;
		sgx_launch_token_t launch_token = { 0 };
		memset(&launch_token, 0, sizeof(sgx_launch_token_t));
	
			ret = sgx_create_enclave(_T(ENCLAVE_PATH),	SGX_DEBUG_FLAG,	&launch_token,	&launch_token_update,	&enclave_id, NULL);
			if (ret != SGX_SUCCESS)
			{
				printf("\nFailed to create enclave");
			}
			else
			{
				printf("\nSuccessfully create enclave.");

			}
			printf("\nEnclaveID %llx", enclave_id);

			ret = enclave_init_ra(enclave_id,	&status,	false,	&context);


			printf("\nenclave_init_ra success.");


		//STEP 8 & 9

		// isv application call uke sgx_ra_get_msg1
		p_msg1_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t)+ sizeof(sgx_ra_msg1_t));//same as step 7
		p_msg1_full->type = TYPE_RA_MSG1;
		p_msg1_full->size = sizeof(sgx_ra_msg1_t);
	
			ret = sgx_ra_get_msg1(context, enclave_id, sgx_ra_get_ga,(sgx_ra_msg1_t*)((uint8_t*)p_msg1_full	+ sizeof(ra_samp_request_header_t)));//the structure of sgx_ra_get_msg1 has sgx_ra_context_t context that define on sgx_ra_init which we need to have inside the enclave
			//second parameter eid is going to be attested
			Sleep(3 * 1000); // Wait 3s between retries pg-186
	
		if (SGX_SUCCESS != ret)
		{
			ret = -1;
			printf("\nError at step 8 & 9");
			
		}
		else
		{
			printf( "\nStep 8:sgx_ra_get_msg1 success");
			printf("\nStep 9:MSG1 body generated");
			PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
		}

		
		//Step 10
		// The ISV application sends msg1 to the SP to get msg2,
		// msg2 needs to be freed when no longer needed.
		printf("\nStep 10: Sending msg1 and expecting msg2 back.\n");


		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",	p_msg1_full,	&p_msg2_full);

		if (ret != 0 || !p_msg2_full) // if ra_network_send_receive success (0 !=0) || !1 (sucess to get msg2); jump to else

		{  
			//unsucess (-1 != 0)  || 0! (err)  => 0||1  =>1 ; jump to if
			printf("\n msg1 failed ");
			
			}

		
		else
		{
			
			//step 11: msg2 recieved
		printf("\nStep 11: MSG2 recived");
			PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,(uint32_t)sizeof(ra_samp_response_header_t)+ p_msg2_full->size);

			fprintf(OUTPUT, "\n MSG2:\n");
			PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);
		

		}

		sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full	+ sizeof(ra_samp_response_header_t));

		//Step 12 & 13

		//web, "On the client side, when msg2 is received the application calls the sgx_ra_proc_msg2() function to generate msg3. "

		uint32_t msg3_size = 0;
		
		
			//pg-133,134,188

			
				ret = sgx_ra_proc_msg2(context,	enclave_id,	sgx_ra_proc_msg2_trusted,sgx_ra_get_msg3_trusted,p_msg2_body,p_msg2_full->size,	&p_msg3,&msg3_size);
			
			if (!p_msg3)
			{
				printf("\nError msg3");
				ret = -1;
			}
		
			else
			{
				fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
				fprintf(OUTPUT, "\nMSG3 - \n");
			}
		

		PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

		p_msg3_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t) + msg3_size);
		if (NULL == p_msg3_full)
		{
			ret = -1;
		
		}
		p_msg3_full->type = TYPE_RA_MSG3;
		p_msg3_full->size = msg3_size;
		if (memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
		{
			printf( "\nError");
			ret = -1;
		
		}

		// The ISV application sends msg3 to the SP to get the attestation result message, attestation result message needs to be freed when
		// no longer needed. 
		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",p_msg3_full,&p_att_result_msg_full);
		


		sample_ra_att_result_msg_t * p_att_result_msg_body =(sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full+ sizeof(ra_samp_response_header_t));
		if (TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
		{
			ret = -1;
			printf( "\nError MSG3 ");
		}
		else
		{
			printf("\nStep 13: Sent MSG3 successfully");
			
			
		}

		printf( "\nStep 15: RESULT recieved - ");
		PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,	p_att_result_msg_full->size);

	
		ret = verify_att_result_mac(enclave_id,	&status,context,(uint8_t*)&p_att_result_msg_body->platform_info_blob,sizeof(ias_platform_info_blob_t),(uint8_t*)&p_att_result_msg_body->mac,	sizeof(sgx_mac_t));
		
		bool attestation_passed = true;

		if (0 != p_att_result_msg_full->status[0] || 0 != p_att_result_msg_full->status[1])
		{
			printf("\nError in attestation ");
		}

		fprintf(OUTPUT, "\nRemote attestation success!");
	}



	ret=enclave_ra_close(enclave_id, &status, context);

	if (ret = 1)
	{
		printf("sgx_ra_close");
	}
	else
	{
		printf("Error at sgx_ra_close");
	}


	sgx_destroy_enclave(enclave_id);


	ra_free_network_response_buffer(p_msg0_resp_full);
	ra_free_network_response_buffer(p_msg2_full);
	ra_free_network_response_buffer(p_att_result_msg_full);

	// p_msg3 is malloc'd by the untrusted KE library. App needs to free.
	SAFE_FREE(p_msg3);
	SAFE_FREE(p_msg3_full);
	SAFE_FREE(p_msg1_full);
	SAFE_FREE(p_msg0_full);
	printf("\nEnter a character before exit ...\n");
	getchar();
	return ret;
}

