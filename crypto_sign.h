#include "api.h"

int crypto_sign(const unsigned char *sk);

int crypto_sign_public_key(
    unsigned char *pk,
    unsigned char *sk
    );

int crypto_sign_open(
    unsigned char *m,unsigned long long *mlen,
    unsigned long long smlen,
    const unsigned char *pk
    );
