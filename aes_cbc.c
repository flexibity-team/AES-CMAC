#include "TI_aes_128.h"
#include "aes_cbc.h"

#include <string.h>

/* função que verifica se bloco contem padding ou não
 * ret 0 caso negativo ou o valor de bytes com pading*/
int existPadding(unsigned char *block) {

	int i = block[B_LAST_INDEX];
	int a;

	for (a = B_LAST_INDEX; a > (B_LAST_INDEX - i); a--) {
		if (block[a] == i) {
			continue;
		} else {
			return 0;
		}
	}
	return i;

}

void aes_cbc_encript(unsigned char *data, int len, unsigned char *key,
		unsigned char *iv, unsigned char *kiv, unsigned char *k1,
		unsigned char *k2, unsigned char *mac) {
	unsigned char state[BLOCK_SIZE];

	unsigned char keyAux[BLOCK_SIZE];

	unsigned char lastState[BLOCK_SIZE];

	int i = 0, e;

	int lastRound = 0;

	int finalLen = 0;
	if (len % BLOCK_SIZE != 0) {
		lastRound = 1;
		finalLen = len % BLOCK_SIZE;
	}

	int nRounds = len / BLOCK_SIZE;

	memcpy(lastState, iv, BLOCK_SIZE);

	//Encrip the IV/nonce using a - k1;
	memcpy(keyAux, kiv, BLOCK_SIZE);
	aes_enc_dec(lastState, keyAux, 0);

	//FOR of cbc chain
	for (; i < nRounds; i++) {

		memcpy(state, &data[i * BLOCK_SIZE], BLOCK_SIZE);

		memcpy(keyAux, key, BLOCK_SIZE);

		//XOR lastState + PlainText(state)
		for (e = 0; e < BLOCK_SIZE; e++) {
			state[e] = state[e] ^ lastState[e];
		}

		// In last round compute the MAC
		if (i == (nRounds - 1) && (!lastRound)) {

			memcpy(lastState, &data[i * BLOCK_SIZE], BLOCK_SIZE);

			/*
			 printf("\n Last State \n");
			 for(e = 0; e < 16; e++){
			 printf("%02x, ",lastState[e] & 0xff);
			 }
			 printf(" \n");
			 */
			//In case of padding  is need will break and do LastRound code
			if (existPadding(lastState) != 0) {
				lastRound = 1;
				break;
			}

			memcpy(mac, state, BLOCK_SIZE);

			// XOR K1 (PlainText is multiple of n blocks)
			for (e = 0; e < BLOCK_SIZE; e++) {
				mac[e] = mac[e] ^ k1[e];
			}

			//AES Encript mac using Key
			memcpy(keyAux, key, BLOCK_SIZE);
			aes_enc_dec(mac, keyAux, 0);
		}

		//AES Encript
		memcpy(keyAux, key, BLOCK_SIZE);
		aes_enc_dec(state, keyAux, 0);

		//Save Criptograma como next "lastState"
		memcpy(lastState, state, BLOCK_SIZE);

		//save cipher text
		memcpy(&data[i * BLOCK_SIZE], state, BLOCK_SIZE);

	}

	if (lastRound) {

		if (finalLen != 0) {

			//ADD Padding
			memcpy(state, &data[(i * BLOCK_SIZE)], finalLen);
			memset(&state[finalLen], (BLOCK_SIZE - finalLen),
					BLOCK_SIZE - finalLen);

			// XOR LastState + PlainText.
			for (e = 0; e < BLOCK_SIZE; e++) {
				state[e] = state[e] ^ lastState[e];
			}
		}

		// In CMAC padded block is Xored with a diferent K (K2).
		memcpy(mac, state, BLOCK_SIZE);

		// XOR LastState + K2(pad used).
		for (e = 0; e < BLOCK_SIZE; e++) {
			mac[e] = mac[e] ^ k2[e];
		}
		//AES Encript mac using Key
		memcpy(keyAux, key, BLOCK_SIZE);
		aes_enc_dec(mac, keyAux, 0);

		//AES Encript
		memcpy(keyAux, key, BLOCK_SIZE);
		aes_enc_dec(state, keyAux, 0);

		/*	printf("print State \n");
		 for(e = 0; e <16 ; e++){
		 printf("%02x",state[e] & 0xff);
		 }
		 */
		memcpy(&data[i * BLOCK_SIZE], state, BLOCK_SIZE);

	}
	/*
	 printf("print MAC \n");
	 for(e = 0; e <16 ; e++){
	 printf("%02x",mac[e] & 0xff);
	 }
	 */
}

int aes_cbc_decript(unsigned char *data, int len, unsigned char *key,
		unsigned char *iv, unsigned char *kiv) {
	unsigned char state[BLOCK_SIZE];

	unsigned char key1[BLOCK_SIZE];

	unsigned char next_xor[BLOCK_SIZE];

	unsigned char ivAux[BLOCK_SIZE];

	int i = 0, e;

	//TODO reject msg outside

	if (len % BLOCK_SIZE != 0) {
		return -1;
	}

	int nRounds = len / BLOCK_SIZE;
	//printf("%d \n",nRounds);

	memcpy(ivAux, iv, BLOCK_SIZE);

	//Encrip de nonce using a key k1
	memcpy(key1, kiv, BLOCK_SIZE);
	aes_enc_dec(ivAux, key1, 0);

	for (; i < nRounds; i++) {

		memcpy(state, &data[i * BLOCK_SIZE], BLOCK_SIZE);

		memcpy(key1, key, BLOCK_SIZE);
		aes_enc_dec(state, key1, 1);

		/*
		 if(i == (nRounds-1)){

		 memcpy(mac,state, 16);

		 //XOR + K2
		 for (e=0;e<16;e++){
		 mac[e]= mac[e] ^ k1[e];
		 }

		 memcpy(key1,key, 16);
		 aes_enc_dec(mac,key1,0);

		 }
		 */

		// Se for a primeira rounda XOR com ivAux, caso contrario  faz com next_xor
		if (i == 0) {
			//	printf("\n primeira ronda \n");
			//XOR ivAux + PlainText
			for (e = 0; e < BLOCK_SIZE; e++) {
				state[e] = state[e] ^ ivAux[e];
			}
		} else {
			//XOR nextXor + PlainText
			for (e = 0; e < BLOCK_SIZE; e++) {
				state[e] = state[e] ^ next_xor[e];
			}
		}

//	printf("\n i-%d \n",i);
		//guarda criptograma como proximo next_xor
		memcpy(next_xor, &data[i * BLOCK_SIZE], BLOCK_SIZE);
		memcpy(&data[i * BLOCK_SIZE], state, BLOCK_SIZE);

	}

	return 0;
}
