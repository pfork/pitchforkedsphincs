#include "api.h"

int pqcrypto_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk);
int pqcrypto_sign_public_key(unsigned char *pk, unsigned char *sk);
int pqcrypto_sign_open(unsigned char *m, const unsigned char *sig, const unsigned char *pk);
