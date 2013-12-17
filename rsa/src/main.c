#include "deriv.h"
#include "protect_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int print_hex(
		unsigned char *buffer, 
		int buffer_len,
		char *id)
{
	int i;

	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}

int main(int argc, char *argv[])

{
	int ret;
	
	unsigned char key[32]; //SHA256 used
	char password[32];
	unsigned char salt[16];
	unsigned int iterations;
	unsigned char input[128];
	int input_len;
	unsigned char *output;
	int output_len;

	/* *** initialization *** */
	strcpy(password, "MonMDP !!!");
	memset(salt, 0x00, 16); //salt = 0x00 ... 0x00
	input_len = 128;
	memset(input, 0x99, input_len);

	iterations = 1<<5; //32
	ret = 1;
	output = NULL;
	
	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, 
			input, input_len, password, salt, 16, iterations);
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	if(ret != 0)
		goto cleanup;



	/********** RSA de la clée ************/


	
	
	
	ret = 0;
cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, 32);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}

