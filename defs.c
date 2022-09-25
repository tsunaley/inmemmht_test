#include "defs.h"

const uchar g_zeroHash[HASH_LEN] = {0x5f, 0xec, 0xeb, 0x66, 0xff, 0xc8, 0x6f, 0x38,
									0xd9, 0x52, 0x78, 0x6c, 0x6d, 0x69, 0x6c, 0x79, 
									0xc2, 0xdb, 0xc2, 0x39, 0xdd, 0x4e, 0x91, 0xb4, 
									0x67, 0x29, 0xd7, 0x3a, 0x27, 0xfb, 0x57, 0xe9};



void nop() {
	return;
}

void println(){
	printf("\n");

	return;
}

char* generate_random_string(int str_len){
	char *tmp_str = NULL;
	int i = 0;

	if(str_len <= 0)
		return NULL;

	tmp_str = (char*) malloc (str_len);
	memset(tmp_str, 0, str_len);

	for(i = 0; i < str_len; i++){
		tmp_str[i] = ASCII_A_POS + rand() % 26;
	}

	return tmp_str;
}

uint32 is_power_of_2(int d){
	return (d & d -1);
}

uint32 cal_the_least_pow2_to_n(uint32 n){
	return (uint32)pow(2,(int)ceil(log10(n)/log10(2)));
}

void check_pointer(void* ptr, const char *ptr_name) {
	if(!ptr){
		printf("Pointer %s is NULL.\n", ptr_name);
	}

	return;
}

bool check_pointer_ex(void* ptr, const char *ptr_name, const char *from, const char *dbg_msg) {
	if(!ptr){
		printf("Pointer %s is NULL. ", ptr_name);
		debug_print(from, dbg_msg);
		return FALSE;
	}

	return TRUE;
}

void debug_print(const char *from, const char *dbg_msg) {
	if(!from || !dbg_msg) {
		printf("DBGMSG ERROR: null message from a null source.\n");
		return;
	}

	printf("DBGMSG: from %s; %s.\n", from, dbg_msg);

	return;
}

void print_buffer_in_byte_hex( uchar *buf, uint32 buf_len){
	int i = 0;

	if(!buf || buf_len <= 0){
		printf("Parameter \"buf\" cannot be NULL, or buf_len cannot be equal to/less than 0.\n");
		return;
	}
	for(i = 0; i < buf_len; i++) {
		printf("%#04x  ", buf[i]);
	}
	printf("\n");
}

/****************************************************************
 *                Get/Set Functions for Global Variables
*****************************************************************/
