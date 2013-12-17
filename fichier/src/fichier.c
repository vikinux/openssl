#include "polarssl/sha256.h"
#include "polarssl/aes.h"
#include <stdio.h>
#include <stdlib.h>


int getSubkey( unsigned char *K, unsigned char *subK, int K_ln, char *salt){


	memcpy( K,(unsigned char *)  salt, 9);
	sha256( K, K_ln, subK, 0);

	return 0;

}


int print_hex(unsigned char *buffer, int buffer_len,char *id)
{
	int i;

	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}

int protect_buffer( unsigned char **output, int *output_len, unsigned char *input, int input_ln, unsigned char *Ki, unsigned char *Kc){



	



}




int main ( int argc, char * argv[]){

	unsigned char  Kc[32];
	unsigned char  Ki[32];
	unsigned char *K = malloc(sizeof(char)*41);
	char *filename;
	File fichier = NULL;
	char * buff;
	char * out;
	long long int taille = 0; 
	int pad_ln = 0;
	int i =0; 
	const unsigned char padding[16] = { "1" , "2" , "3" ,"4","5","6","7","8","9","10","11","12","13","14","15","16"};


	filename = malloc(sizeof(char)*32);
	filename = argv[1];

	K = (unsigned char *) argv[2];

	getSubkey(K, Kc, 42, "123456789");
	getSubkey(K, Ki, 42, "987654321");


	print_hex( Kc, 32, "Kc = ");
	print_hex( Ki, 32, "Ki = ");


	fichier = fopen( filename, r);

	fseek(fichier, 0, SEEK_END);
	taille = ftell(fichier);
	rewind(fichier);

	pad_ln = 16 - (taille %16);


	buff = malloc(sizeof(char)*taille);
	out = malloc(sizeof(char)*(taille + pad_ln + 32);
		
	fread( buff, sizeof(char), taille, fichier);
	

	for(i =0, i > 0; i--)
		memcpy(buff, padding[16-i],1); 


	protect_buffer( out, 
	return 0;

}
