#include "api.h"

int pqcrypto_sign(const unsigned char *sk, unsigned char *m, unsigned int mlen, unsigned char *sig);

int pqcrypto_sign_public_key(
    unsigned char *pk,
    unsigned char *sk
    );

int pqcrypto_sign_open(
    unsigned char* sig,
    const unsigned char *m, const unsigned long long mlen,
    const unsigned char *pk
    );
