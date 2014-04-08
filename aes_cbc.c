#include "TI_aes_128.h"

void aes_cbc_encript(unsigned char *data, int len, unsigned char *key, unsigned char iv[],unsigned char *k1,unsigned char *k2, unsigned char *mac)
{
	unsigned char state[16];
	
	unsigned char key1[16];
		
	int i = 0,e;
	
	int lastRound = 0;
	
	int finallen;
	if (len % 16 != 0) {
	lastRound=1;
	finallen = len % 16;
	}
	int rondas= len/16;


	//Encrip de nonce using a key k1
	memcpy(key1,k1, 16);
	aes_enc_dec(iv,key1,0);
	
	for(; i < rondas;i++){
				
	memcpy(state, &data[i*16], 16);
	memcpy(key1,key, 16);

	//XOR IV + PlainText
	for (e=0;e<16;e++){
		state[e]= state[e] ^ iv[e];
		}
	
	
	if(i == (rondas-1) && (!lastRound)){
		//Calcula MAC
		memcpy(mac,state,16);
		printf("\n XOR with k1 \n ");
		// XOR (IV + PlainText) + k1 
		for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k1[e];
			}
		}
	
	//AES Encript	
	aes_enc_dec(state,key1,0);
	
	//Save Criptograma como next "IV"
	memcpy(iv,state,16);
	
	//save cipher text
	memcpy(&data[i*16],iv, 16);
	
	}
	
	if(lastRound){
	
	printf("\n LAST Round \n");	
	
	// Padding
	memcpy(state, &data[(i*16)],finallen);
	memset(&state[finallen],'/0',16-finallen);
	memcpy(key1,key, 16);
	
	
	// XOR IV + PlainText.
	for (e=0;e<16;e++){
		state[e]= state[e] ^ iv[e];
		}	
	
	// In CMAC padding text is Xored with a diferent K.
	memcpy(mac,state,16);
	for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k2[e];
			}
	
	//AES Encript		
	aes_enc_dec(state,key1,0);
	
/*	printf("print State \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/	
	memcpy(&data[i*16],state, 16);	
		
		}
		
	printf("print MAC \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",mac[e] & 0xff);
		}
	
}



void aes_cbc_decript(unsigned char *data, int len, unsigned char *key,unsigned char iv[],unsigned char *k1,unsigned char *k2,unsigned char *mac)
{
	unsigned char state[16];

	unsigned char key1[16];

//	unsigned char mac[16];
	
	unsigned char next_xor[16];
	
	int i = 0,e;
	
	int lastRound = 0;
	
	int finallen;

	if (len % 16 != 0) {
	printf("\n Error: menssagem mal formatada (numero de blocos não inteiro) \n");
//	lastRound=1;
//	finallen = len % 16;
	}
	int rondas= len/16;
	//printf("%d \n",rondas);
	
	
	//Encrip de nonce using a key k1
	memcpy(key1,k1, 16);
	aes_enc_dec(iv,key1,0);
	
	for(; i < rondas;i++){
			
	memcpy(state, &data[i*16], 16);
	memcpy(key1,key, 16);
	
//  guarda criptograma como proximo next_xor
//	memcpy(next_xor,&data[i*16],16);
	
/*
	printf("print State \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/
/*
	printf("print key \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",key[e] & 0xff);
		}
*/
	aes_enc_dec(state,key1,1);
	
	// Se for a primeira rounda XOR com IV, caso contrario  faz com next_xor
	
		if(i== (rondas-1)){
		memcpy(mac,state,16);
		//XOR IV + PlainText
		for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k1[e];
			}
			
			
	printf("print MAC \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",mac[e] & 0xff);
		}	
		}
	
	
	if(i==0){
	//	printf("\n primeira ronda \n");
		//XOR IV + PlainText
		for (e=0;e<16;e++){
			state[e]= state[e] ^ iv[e];
			}			
		}else{
			//XOR IV + PlainText
			for (e=0;e<16;e++){
				state[e]= state[e] ^ next_xor[e];
				}
			}
			
		
/*	
	printf("print State decr \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/	

//	printf("\n i-%d \n",i);
	//guarda criptograma como proximo next_xor
	memcpy(next_xor,&data[i*16],16);
	memcpy(&data[i*16],state, 16);
	
	}

/*	
	if(lastRound){

	printf("\n last Round \n ");
	memcpy(state, &data[(i*16)],finallen);
	memset(&state[finallen],'/0',16-finallen);
	memcpy(key1,key, 16);
	
/*	printf("print State \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/		
/*
	aes_enc_dec(state,key1,1);
	
	//XOR IV + PlainText
	for (e=0;e<16;e++){
		state[e]= state[e] ^ next_xor[e];
	}
	
/*	printf("print State \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/
/*		
	memcpy(&data[i*16],state, 16);	
		
		}
		*/
}
