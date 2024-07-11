#ifndef _UTILCRYPTO_

#define _UTILCRYPTO_

char *encrypt_password(char *password, char *salt);
char* calculate_sha256(const char *data, unsigned int data_len, unsigned char *hash);

#endif