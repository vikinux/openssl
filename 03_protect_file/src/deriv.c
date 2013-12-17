#include "deriv.h"
#include "polarssl/sha256.h"

#include <string.h>
#include <stdlib.h>

int deriv_passwd(unsigned char *key,
		char *password,
		unsigned char *salt, int salt_len,
		unsigned int iterations)
{
	int ret;
	unsigned int i;
	unsigned char hash[32];
	sha256_context ctx;

	/* *** Init *** */
	ret = 1; // error
	i = 0;

	/* *** Check args *** */
	if((key == NULL) || (password == NULL) || (salt == NULL) 
			|| (salt_len <= 0) || (iterations == 0))
		goto cleanup;


	/* *** Get H0 *** */
	sha256_starts(&ctx, 0);

	sha256_update(&ctx, (unsigned char *)password, strlen(password));
	sha256_update(&ctx, salt, salt_len);
	sha256_update(&ctx, (unsigned char *)&i, sizeof(int));
	
	sha256_finish(&ctx, hash); //hash == HO

	/* *** Hi *** */
	for(i = 1; i < iterations; i++)
	{
		sha256_starts(&ctx, 0);

		sha256_update(&ctx, hash, 32);
		sha256_update(&ctx, (unsigned char *)password, strlen(password));
		sha256_update(&ctx, salt, salt_len);
		sha256_update(&ctx, (unsigned char *)&i, sizeof(int));

		sha256_finish(&ctx, hash);
	}
	memcpy(key, hash, 32);

	ret = 0; // success

cleanup:

	memset(&ctx, 0x00, sizeof(sha256_context));
	memset(hash, 0x00, 32);
	return ret;
}
