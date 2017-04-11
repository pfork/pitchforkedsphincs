#include "pqcrypto_sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define MLEN 32

int main(void) {
  unsigned char sphincs_key[PQCRYPTO_SECRETKEYBYTES]; // first used for sk, then for pk
  unsigned char msg[32]={0};
  unsigned char sig[PQCRYPTO_BYTES];
  int i;

  for(i=0; i<PQCRYPTO_SECRETKEYBYTES; i++) sphincs_key[i] = 12; // placeholder value
  pqcrypto_sign_public_key(sphincs_key, sphincs_key);

  assert(fread(sig,sizeof sig,1,stdin)==1);
  unsigned char x = (unsigned char)pqcrypto_sign_open(msg, sig, sphincs_key);
  printf("%d", x);
  return 0;
}
