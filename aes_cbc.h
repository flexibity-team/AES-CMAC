
int existPadding(unsigned char *block);

void aes_cbc_encript(unsigned char *data, int len, unsigned char*key,unsigned char *iv,unsigned char *k1,unsigned char *k2,unsigned char *mac);

void aes_cbc_decript(unsigned char *data, int len, unsigned char *key,unsigned char *iv,unsigned char *k1);
