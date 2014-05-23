#include "TI_aes_128.h"

#include <sys/types.h>
#include <inttypes.h>

/*função que verifica se bloco contem padding ou não 
 * ret 0 caso negativo ou o valor de bytes com pading*/
int existPadding(unsigned char *block){

int i = block[15];	
int a;	

		for(a = 15; a > (15-i) ; a--){
			if(block[a] == i){				
			continue;
		}else{return 0;}
	}
return i;
	
}

void aes_cbc_encript(unsigned char *data, int len, unsigned char *key, unsigned char iv[],unsigned char *k1,unsigned char *k2, unsigned char *mac)
{
	unsigned char state[16];
	
	unsigned char keyAux[16];
	
	unsigned char lastState[16];
		
	int i = 0, e;
	
	int lastRound = 0;
	
	int finalLen = 0;
	if (len % 16 != 0) {
	lastRound =1;
	finalLen = len % 16;
	}
	
	int nRounds= len/16;

	memcpy(lastState,iv, 16);

	//Encrip the IV/nonce using a - k1;
	memcpy(keyAux,k1, 16);
	aes_enc_dec(lastState,keyAux,0);
	
	//for of cbc chain
	for(; i < nRounds;i++){
				
	memcpy(state, &data[i*16], 16);
	memcpy(keyAux,key, 16);

	//XOR lastState + PlainText(state)
	for (e=0;e<16;e++){
		state[e]= state[e] ^ lastState[e];
		}
	
	//In last round compute the MAC
	if(i == (nRounds-1) && (!lastRound)){
		printf("Last round wihtout padding \n");
	
	memcpy(lastState, &data[i*16], 16);	

/*			
	printf("\n Last State \n");
	for(e = 0; e < 16; e++){
		printf("%02x, ",state[e] & 0xff);	
		}
	printf(" \n");
*/	
		if(existPadding(state)!=0){
			printf("padding detected without paddig \n");	
			lastRound=1;
			break;
			}
		
		memcpy(mac,state,16);
		
		// XOR K1 (PlainText is multiple of n blocks) 
		for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k1[e];
			}
			
			//AES Encript mac using Key
			memcpy(keyAux,key, 16);
			aes_enc_dec(mac,keyAux,0);
		}

	//AES Encript
	memcpy(keyAux,key,16);	
	aes_enc_dec(state,keyAux,0);
	
	//Save Criptograma como next "lastState"
	memcpy(lastState,state,16);
	
	//save cipher text
	memcpy(&data[i*16],state, 16);
	
	}
	
	if(lastRound){
	
	printf("\n LAST Round \n");	
	
	if(finalLen != 0){
		
	printf("lets add padding \n");
		
	//ADD Padding 
	memcpy(state, &data[(i*16)],finalLen);
	memset(&state[finalLen],(16-finalLen),16-finalLen);
	}
	
	// XOR LastState + PlainText.
	for (e=0;e<16;e++){
		state[e]= state[e] ^ lastState[e];
		}	
	
	// In CMAC padding text is Xored with a diferent K.
	memcpy(mac,state,16);
	
	// XOR LastState + K2(pad used).
	for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k2[e];
			}
	//AES Encript mac using Key
	memcpy(keyAux,key, 16);
	aes_enc_dec(mac,keyAux,0);
	
	//AES Encript	
	memcpy(keyAux,key, 16);	
	aes_enc_dec(state,keyAux,0);
	
/*	printf("print State \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",state[e] & 0xff);
		}
*/	
	memcpy(&data[i*16],state, 16);	
		
		}
/*		
	printf("print MAC \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",mac[e] & 0xff);
		}
	*/
}



void aes_cbc_decript(unsigned char *data, int len, unsigned char *key,unsigned char iv[],unsigned char *k1,unsigned char *k2,unsigned char *mac)
{
	unsigned char state[16];


	unsigned char key1[16];
	
	unsigned char next_xor[16];
	
	int i = 0,e;
	
	int lastRound = 0;
	
	uint8_t finallen;

	if (len % 16 != 0) {
	printf("\n Error: menssagem mal formatada (numero de blocos não inteiro) \n");
//	lastRound=1;
//	finallen = len % 16;
	}
	int nRounds= len/16;
	//printf("%d \n",nRounds);
	
	
	//Encrip de nonce using a key k1
	memcpy(key1,k1, 16);
	aes_enc_dec(iv,key1,0);
	
	for(; i < nRounds;i++){
			
	memcpy(state, &data[i*16], 16);
	
	memcpy(key1,key, 16);
	aes_enc_dec(state,key1,1);
	
		if(i == (nRounds-1)){
		
		memcpy(mac,state, 16);
		
		//XOR + K2
		for (e=0;e<16;e++){
			mac[e]= mac[e] ^ k1[e];
			}
		
		memcpy(key1,key, 16);		
		aes_enc_dec(mac,key1,0);
		
		}
	
	// Se for a primeira rounda XOR com IV, caso contrario  faz com next_xor
	
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
		
//	printf("\n i-%d \n",i);
	//guarda criptograma como proximo next_xor
	memcpy(next_xor,&data[i*16],16);
	memcpy(&data[i*16],state, 16);
	
	}


}
