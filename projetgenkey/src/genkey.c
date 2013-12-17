#include <stdio.h>
#include <stdlib.h>
#include "polarssl/havege.h"


int gen_key( unsigned char *key, int key_lenght){

	int i = 0;
	int ret = 1;

	havege_state *hs = malloc(sizeof( havege_state))  ;

	if( hs == NULL )
		return -1;


	havege_init(hs);		

	ret = havege_random( hs, key, key_lenght); 

	for( i= 0; i < key_lenght; i++)
		printf("%c",key[i]);

	free(hs);
	
	return ret;
}


int main( int  argc, char * argv[] ){

	unsigned char *key;

	if( argc != 2 ){
		printf("ERROR\n");
		return 0;
	}
	int key_lenght = atoi(argv[1]);

	key = malloc( sizeof(unsigned char) * key_lenght);

	if( key == NULL )
		return -1;
		

	gen_key(key, key_lenght);

	free(key);

	return 0;
}
