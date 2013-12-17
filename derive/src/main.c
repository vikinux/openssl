#include "deriv.h"
#include <stdio.h>
#include <stdlib.h>
int print_hex(unsigned char *buffer, int buffer_len,char *id)
{
	int i;

	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}


int main(int argc, char * argv[]){



	unsigned char key[32];
	char *pwd;
	unsigned char * salt;


	/* *** initialization *** */

	if(argc != 3)
	{
		fprintf(stderr, "usage: %s <passwd>\n", argv[0]);
		return -1;
	}



	/* *** allocate space for salt *** */
	salt = (unsigned char *)malloc( 32 * sizeof(char));
	if(key == NULL)
	{
		fprintf(stderr, "error: can't allocate enough space for salt\n");
		return -1;
	}


	/* *** allocate space for pwd *** */
	pwd = (char *)malloc( 64 * sizeof(char));
	if(pwd == NULL)
	{
		fprintf(stderr, "error: can't allocate enough space for passwd\n");
		return -1;
	}

	salt = (unsigned char *) argv[2];
	pwd = argv[1];

	deriv_passwd( key, pwd, salt, 9, 32);

	print_hex( key, 32, "hash =");

	return 0;
}
