#include "pqcrypto_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int main(void) {
  unsigned char sphincs_sk[PQCRYPTO_SECRETKEYBYTES];
  unsigned char msg[32]={0};
  unsigned char sig[PQCRYPTO_BYTES];
  int i;
  for(i=0; i<PQCRYPTO_SECRETKEYBYTES; i++) sphincs_sk[i] = 12;
  memset(sig,0,sizeof sig);
  pqcrypto_sign(sig, msg, sphincs_sk);
  assert(fwrite(sig,sizeof sig,1,stdout)==1);
  return 0;
}
