#include "deriv.h"
#include "polarssl/sha256.h"
#include <string.h>


int deriv_passwd(unsigned char *key,char *password,unsigned char *salt, int salt_len,unsigned int iterations){

	int ret = 1, i;
	unsigned char * tmp = malloc(sizeof(char) * 32);

	memcpy( password, salt, 32);
	tmp = (unsigned char *) password;


	sha256( (unsigned char *) password, strlen((char *) password), key, 0);
	tmp = key;


	for( i = 1; i < iterations ; i++){
		sha256(tmp, strlen((char *) password), key, 0);
		tmp = key;
	}
return ret;
}


