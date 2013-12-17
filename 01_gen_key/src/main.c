#include "gen_key.h"
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
	unsigned char *key;
	int key_length;

	/* *** initialization *** */
	key = NULL;
	ret = 1;
	
	/* *** check cmd line argument *** */
	if(argc != 2)
	{
		fprintf(stderr, "usage: %s <key_length>\n", argv[0]);
		return -1;
	}
	key_length = atoi(argv[1]);
	if(key_length <= 0)
	{
		fprintf(stderr, "error: key_length must be > 0\n");
		return -1;
	}
	
	/* *** allocate space for key *** */
	key = (unsigned char *)malloc(key_length * sizeof(char));
	if(key == NULL)
	{
		fprintf(stderr, "error: can't allocate enough space for key\n");
		return -1;
	}
	
	/* *** generate key *** */
	ret = gen_key(key, key_length);
	if(ret != 0)
		goto cleanup;
	
	/* *** print the key *** */
	print_hex(key, key_length, "key = ");
	
	ret = 0;
cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, key_length);
	free(key);
	key = NULL;

	return ret;
}
