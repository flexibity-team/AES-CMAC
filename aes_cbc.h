
// tamanho do "MAC" associado a cada mensagen
#define MACLENGHT 4

void aes_cbc_encript(unsigned char *data, int len, unsigned char*key,unsigned char iv[],unsigned char *k1,unsigned char *k2,unsigned char *mac);

void aes_cbc_decript(unsigned char *data, int len, unsigned char *key,unsigned char iv[],unsigned char *k1,unsigned char *k2,unsigned char *mac);
