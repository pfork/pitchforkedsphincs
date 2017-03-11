#ifndef HORST_H
#define HORST_H

#include "params.h"

typedef struct
{
  unsigned int idx;
  unsigned char level;
  unsigned char hash[HASH_BYTES];
} node;

int horst_sign(unsigned char *sig,
               unsigned char pk[HASH_BYTES],
               const unsigned char seed[SEED_BYTES],
               const unsigned char masks[2*HORST_LOGT*HASH_BYTES],
               const unsigned char m_hash[MSGHASH_BYTES]);

int horst_verify(unsigned char* sig, unsigned char *pk, const unsigned char masks[2*HORST_LOGT*HASH_BYTES], const unsigned char m_hash[MSGHASH_BYTES]);

#endif
