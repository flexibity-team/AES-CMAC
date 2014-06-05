#include "aes_cbc.h"
#include <sys/types.h>
#include <inttypes.h>

int main(int argc, const char *argv[])
{                                	
	
	uint8_t data[] = 
	
{ 
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17};
	
	uint8_t key[] = 
	{ 
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
		
	uint8_t k1[] = 
	{ 
		0x12, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00};
		
	uint8_t k2[] = 
	{ 
		0x13, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00};		
		
	uint8_t iv[]=
	
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
		

	unsigned char mac[BLOCK_SIZE];
	unsigned char mac_rev[BLOCK_SIZE];
	
	int len = sizeof(data);
	int e = 0;

/*	
	printf("\n DATA \n");
	for(e = 0; e < len; e++){
		printf("%02x, ",data[e] & 0xff);
		}
*/

	int finallen=BLOCK_SIZE;
	if (len % BLOCK_SIZE != 0) {
	finallen = len % BLOCK_SIZE;
	}
		
	uint8_t newdata[len+(BLOCK_SIZE-finallen)];
	uint8_t newdata1[len+(BLOCK_SIZE-finallen)];
	
	memcpy(newdata,data,len);
	aes_cbc_encript(newdata,len,key,iv,k1,k2,mac);
	
/*	
	printf("print MAC \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",mac[e] & 0xff);
		}
*/
	int lenNew = sizeof(newdata);
/*
	printf("\n Cripto \n");
	for(e = 0; e < lenNew ; e++){
		printf("%02x, ",newdata[e] & 0xff);
		}
*/	
	/* Send newdata to receiver*/

	/* receiver decypher msg */	
	aes_cbc_decript(newdata,lenNew,key,iv,k1);
	
/*	printf("\n DATA \n");
	for(e = 0; e < lenNew; e++){
		printf("%02x, ",newdata[e] & 0xff);
		}
*/
	
	/* receiver compute MAC of msg to be compare */
	memcpy(newdata1,newdata,len);
	aes_cbc_encript(newdata1,len,key,iv,k1,k2,mac_rev);
	
	/* Compare MAC's to validate msg*/
	
	if(memcmp(mac,mac_rev,BLOCK_SIZE)==0){
		printf("\n MAC Equals msg is Valid \n");
		}
	
/*	
	printf("print MAC \n"); 
	for(e = 0; e <16 ; e++){
		printf("%02x",mac[e] & 0xff);
		}
*/

/*	printf("\n DATA \n");
	for(e = 0; e < lenNew; e++){
		printf("%02x, ",newdata[e] & 0xff);
		}
*/	
	if(memcmp(data,newdata,len)==0){
		printf("\n DATA Correctly decipher \n");
		}
	
	
return 0;
}
