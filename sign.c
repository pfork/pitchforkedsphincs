#include "crypto_sign.h"
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "zerobytes.h"
#include "params.h"
#include "wots.h"
#include "horst.h"
#include "hash.h"
#include "stm32wrapper.h"
#include "blake512/ref/hash.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define BIGINT_BYTES ((TOTALTREE_HEIGHT-SUBTREE_HEIGHT+7)/8)

// unfortunately this cannot be much higher, as blake512_update does not
// seem to support updates of 1024 bits or more, after the first one
#define MBLOCKSIZE 64

#if (TOTALTREE_HEIGHT-SUBTREE_HEIGHT) > 64
#error "TOTALTREE_HEIGHT-SUBTREE_HEIGHT must be at most 64" 
#endif

typedef struct{
  int level;
  unsigned long long subtree;
  int subleaf;
} leafaddr;


static void get_seed(unsigned char seed[SEED_BYTES], const unsigned char *sk, const leafaddr *a)
{
#if (N_LEVELS > 15) && (N_LEVELS < 8)
#error "Need to have 8 <= N_LEVELS <= 15"
#endif

#if SUBTREE_HEIGHT != 5
#error "Need to have SUBTREE_HEIGHT == 5"
#endif

#if TOTALTREE_HEIGHT != 60
#error "Need to have TOTALTREE_HEIGHT == 60"
#endif
  unsigned char buffer[SEED_BYTES+8];
  unsigned long long t;
  int i;

  for(i=0;i<SEED_BYTES;i++)
    buffer[i] = sk[i];

  //4 bits to encode level
  t  = a->level;
  //55 bits to encode subtree
  t |= a->subtree << 4;
  //5 bits to encode leaf
  t |= (unsigned long long)a->subleaf << 59;

  for(i=0;i<8;i++)
    buffer[SEED_BYTES+i] = (t >> 8*i) & 0xff;
  
#if SEED_BYTES != HASH_BYTES
#error "Need to have SEED_BYTES == HASH_BYTES"
#endif
  varlen_hash(seed,buffer,SEED_BYTES+8);
}


static void l_tree(unsigned char *leaf, unsigned char *wots_pk, const unsigned char *masks)
{
  int l = WOTS_L;
  int i,j = 0;
  for(i=0;i<WOTS_LOG_L;i++)
  {
    for(j=0 ;j < (l>>1);j++)
      hash_2n_n_mask(wots_pk+j*HASH_BYTES,wots_pk+j*2*HASH_BYTES, masks+i*2*HASH_BYTES);

    if(l&1)
    {
      memcpy(wots_pk+(l>>1)*HASH_BYTES,wots_pk+(l-1)*HASH_BYTES, HASH_BYTES);
      l=(l>>1)+1;
    } 
    else 
      l=(l>>1);
  }
  memcpy(leaf,wots_pk,HASH_BYTES);
}


static void gen_leaf_wots(unsigned char leaf[HASH_BYTES], const unsigned char *masks, const unsigned char *sk, const leafaddr *a)
{
  unsigned char seed[SEED_BYTES];
  unsigned char pk[WOTS_L*HASH_BYTES];

  get_seed(seed, sk, a);
  wots_pkgen(pk, seed, masks);

  l_tree(leaf, pk, masks); 
}


static void treehash(unsigned char *node, int height, const unsigned char *sk, const leafaddr *leaf, const unsigned char *masks)
{

  leafaddr a = *leaf;
  int lastnode,i;
  unsigned char stack[(height+1)*HASH_BYTES];
  unsigned int  stacklevels[height+1];
  unsigned int  stackoffset=0;
  unsigned int maskoffset =0;

  lastnode = a.subleaf+(1<<height);

  for(;a.subleaf<lastnode;a.subleaf++) 
  {
    gen_leaf_wots(stack+stackoffset*HASH_BYTES,masks,sk,&a);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    while(stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {
      //MASKS
      maskoffset = 2*(stacklevels[stackoffset-1] + WOTS_LOG_L)*HASH_BYTES;
      hash_2n_n_mask(stack+(stackoffset-2)*HASH_BYTES,stack+(stackoffset-2)*HASH_BYTES,
          masks+maskoffset);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
  }
  for(i=0;i<HASH_BYTES;i++)
    node[i] = stack[i];
}


static void validate_authpath(unsigned char root[HASH_BYTES], const unsigned char leaf[HASH_BYTES], unsigned int leafidx, const unsigned char *authpath, const unsigned char *masks, unsigned int height)
{
  int i,j;
  unsigned char buffer[2*HASH_BYTES];

  if(leafidx&1)
  {
    for(j=0;j<HASH_BYTES;j++)
      buffer[HASH_BYTES+j] = leaf[j];
    for(j=0;j<HASH_BYTES;j++)
      buffer[j] = authpath[j];
  }
  else
  {
    for(j=0;j<HASH_BYTES;j++)
      buffer[j] = leaf[j];
    for(j=0;j<HASH_BYTES;j++)
      buffer[HASH_BYTES+j] = authpath[j];
  }
  authpath += HASH_BYTES;

  for(i=0;i<height-1;i++)
  {
    leafidx >>= 1;
    if(leafidx&1)
    {
      hash_2n_n_mask(buffer+HASH_BYTES,buffer,masks+2*(WOTS_LOG_L+i)*HASH_BYTES);
      for(j=0;j<HASH_BYTES;j++)
        buffer[j] = authpath[j];
    }
    else
    {
      hash_2n_n_mask(buffer,buffer,masks+2*(WOTS_LOG_L+i)*HASH_BYTES);
      for(j=0;j<HASH_BYTES;j++)
        buffer[j+HASH_BYTES] = authpath[j];
    }
    authpath += HASH_BYTES;
  }
  hash_2n_n_mask(root,buffer,masks+2*(WOTS_LOG_L+height-1)*HASH_BYTES);
}


static void compute_authpath_wots(unsigned char root[HASH_BYTES], const leafaddr *a, const unsigned char *sk, const unsigned char *masks, unsigned int height)
{
  int i, idx, j;
  leafaddr ta = *a;

  unsigned char tree[2*(1<<SUBTREE_HEIGHT)*HASH_BYTES]; // 2 * 32 * 32 = 2KB
  unsigned char seed[SEED_BYTES];
  unsigned char pk[WOTS_L*HASH_BYTES]; //  67 * 32 = 2144B

  for(ta.subleaf = 0; ta.subleaf < (1<<SUBTREE_HEIGHT); ta.subleaf++) {
    // level 0
    get_seed(seed, sk, &ta);
    wots_pkgen(pk, seed, masks);
    l_tree(tree + (1<<SUBTREE_HEIGHT)*HASH_BYTES + ta.subleaf * HASH_BYTES,
        pk, masks);
  }

  int level = 0;

  // tree
  for (i = (1<<SUBTREE_HEIGHT); i > 0; i>>=1)
  {
    for (j = 0; j < i; j+=2)
      hash_2n_n_mask(tree + (i>>1)*HASH_BYTES + (j>>1) * HASH_BYTES, 
          tree + i*HASH_BYTES + j * HASH_BYTES,
          masks+2*(WOTS_LOG_L + level)*HASH_BYTES);

    level++;
  }

  idx = a->subleaf;

  // copy authpath
  for(i=0;i<height;i++) {
    while (!dma_done()); dma_transmit(tree + ((1<<SUBTREE_HEIGHT)>>i)*HASH_BYTES + ((idx >> i) ^ 1) * HASH_BYTES, HASH_BYTES);
  }
  // copy root
  memcpy(root, tree+HASH_BYTES, HASH_BYTES);
}

static void add_message_to_hash(blake512_state* S, blake512_state* check, unsigned char* buffer, unsigned int mleft) {
  if (mleft > MBLOCKSIZE) {
    dma_request(buffer, MBLOCKSIZE); while(!dma_done());
    mleft -= MBLOCKSIZE;
    while (mleft > 2*MBLOCKSIZE) {
      dma_request(buffer+MBLOCKSIZE, MBLOCKSIZE);
      blake512_update(S, buffer, MBLOCKSIZE * 8);
      blake512_update(check, buffer, MBLOCKSIZE * 8);
      while(!dma_done()); dma_request(buffer, MBLOCKSIZE);
      blake512_update(S, buffer+MBLOCKSIZE, MBLOCKSIZE * 8);
      blake512_update(check, buffer+MBLOCKSIZE, MBLOCKSIZE * 8);
      mleft -= 2*MBLOCKSIZE;
      while(!dma_done());
    }
    if (mleft > MBLOCKSIZE) {
      dma_request(buffer+MBLOCKSIZE, MBLOCKSIZE);
      blake512_update(S, buffer, MBLOCKSIZE * 8);
      blake512_update(check, buffer, MBLOCKSIZE * 8);
      while(!dma_done());
      blake512_update(S, buffer+MBLOCKSIZE, MBLOCKSIZE * 8);
      blake512_update(check, buffer+MBLOCKSIZE, MBLOCKSIZE * 8);
      dma_request(buffer, mleft);
      while(!dma_done());
      blake512_update(S, buffer, mleft * 8);
      blake512_update(check, buffer, mleft * 8);
    }
    else if (mleft > 0) {
      dma_request(buffer+MBLOCKSIZE, mleft);
      blake512_update(S, buffer, MBLOCKSIZE * 8);
      blake512_update(check, buffer, MBLOCKSIZE * 8);
      while(!dma_done());
      blake512_update(S, buffer+MBLOCKSIZE, mleft * 8);
      blake512_update(check, buffer+MBLOCKSIZE, mleft * 8);
    }
    else {
      blake512_update(S, buffer, MBLOCKSIZE * 8);
      blake512_update(check, buffer, MBLOCKSIZE * 8);
    }
  }
  else {
    dma_request(buffer, mleft);
    while(!dma_done());
    blake512_update(S, buffer, mleft*8);
    blake512_update(check, buffer, mleft*8);
  }
}

int crypto_sign(const unsigned char *sk)
{
  leafaddr a;
  int i;
  unsigned long long leafidx;
  unsigned char R[MESSAGE_HASH_SEED_BYTES];
  unsigned char m_h[MSGHASH_BYTES];
  unsigned char checkbuf[MSGHASH_BYTES];
  unsigned char buffer[2*MBLOCKSIZE];
  unsigned long long *rnd = (unsigned long long *)buffer;
  unsigned int mleft;

#if 2*MBLOCKSIZE < HASH_BYTES+SEED_BYTES
#error "buffer is not large enough to hold seed and root"
#endif

  // create leafidx deterministically
  {
    while(!dma_done()); dma_request(&mleft, 4);
#ifdef NOCOMMS
    mleft = 32;
#endif
    blake512_state S;
    blake512_state check;
    blake512_init(&S);
    blake512_init(&check);
    blake512_update(&S, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES, SK_RAND_SEED_BYTES*8);
    while(!dma_done());

    add_message_to_hash(&S, &check, buffer, mleft);

    blake512_final( &S, rnd );
    blake512_final( &check, checkbuf );

#if TOTALTREE_HEIGHT != 60
#error "Implemented for TOTALTREE_HEIGHT == 60!"
#endif

    leafidx = rnd[0] & 0xfffffffffffffff;

#if MESSAGE_HASH_SEED_BYTES != 32
#error "Implemented for MESSAGE_HASH_SEED_BYTES == 32!"
#endif
    memcpy(R, &rnd[2], MESSAGE_HASH_SEED_BYTES);

    blake512_init(&S);
    blake512_init(&check);
    blake512_update(&S, R, MESSAGE_HASH_SEED_BYTES*8);

    // construct pk
    leafaddr a;
    a.level = N_LEVELS - 1;
    a.subtree = 0;
    a.subleaf=0;

    // like with the MBLOCKSIZE, this loop is needed since blake512_update does
    // not seem to support updates of 1024 bits or more, after the first one
    for(i=0; i<N_MASKS*HASH_BYTES; i += HASH_BYTES*2)
      blake512_update(&S, sk+SEED_BYTES+i, 32*2*8);

    treehash(buffer, SUBTREE_HEIGHT, sk, &a, sk+SEED_BYTES);
    blake512_update(&S, buffer, HASH_BYTES * 8);

    // there is some gain in moving the first dma request up out of this call
    add_message_to_hash(&S, &check, buffer, mleft);
    blake512_final( &check, m_h );

    // this prevents streaming in two different messages
    if (memcmp(checkbuf, m_h, MSGHASH_BYTES)) {
      return -1;
    }
    blake512_final( &S, m_h );
  }
  a.level   = N_LEVELS; // Use unique value $d$ for HORST address.
  a.subleaf = leafidx & ((1<<SUBTREE_HEIGHT)-1);
  a.subtree = leafidx >> SUBTREE_HEIGHT;

  dma_transmit(R, MESSAGE_HASH_SEED_BYTES);

  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++) {
    buffer[i] = (leafidx >> 8*i) & 0xff;
  }
  while (!dma_done()); dma_transmit(buffer, (TOTALTREE_HEIGHT+7)/8);

  get_seed(buffer, sk, &a);
  horst_sign(buffer+SEED_BYTES, buffer, sk+SEED_BYTES, m_h);

  for(i=0;i<N_LEVELS;i++)
  {
    a.level = i;

    get_seed(buffer, sk, &a);
    wots_sign(buffer+SEED_BYTES, buffer, sk+SEED_BYTES);
    compute_authpath_wots(buffer+SEED_BYTES, &a, sk, sk+SEED_BYTES,SUBTREE_HEIGHT);

    a.subleaf = a.subtree & ((1<<SUBTREE_HEIGHT)-1);
    a.subtree >>= SUBTREE_HEIGHT;
  }

  while (!dma_done());

  return 0;
}

int crypto_sign_public_key(unsigned char *pk, unsigned char *sk)
{
  leafaddr a;

  // randombytes(sk,CRYPTO_SECRETKEYBYTES); STM32L100C-DISCO has no RNG
  memcpy(pk,sk+SEED_BYTES,N_MASKS*HASH_BYTES);

  // Initialization of top-subtree address
  a.level   = N_LEVELS - 1;
  a.subtree = 0;
  a.subleaf = 0;

  // Construct top subtree
  treehash(pk+(N_MASKS*HASH_BYTES), SUBTREE_HEIGHT, sk, &a, pk);
  return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, unsigned long long smlen, const unsigned char *pk)
{
  unsigned long long i;
  unsigned long long leafidx=0;
  unsigned char buffer[2*(WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES)];
  unsigned char *bufp;
  unsigned char pkhash[HASH_BYTES];
  unsigned char root[HASH_BYTES];
  unsigned char tpk[CRYPTO_PUBLICKEYBYTES];
  unsigned char m_h[MSGHASH_BYTES];

  dma_request(buffer + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES, smlen - CRYPTO_BYTES); // message
  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++)
    tpk[i] = pk[i];
  while (!dma_done());
  memcpy(m, buffer + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES, smlen - CRYPTO_BYTES);
  *mlen = smlen - CRYPTO_BYTES;

  dma_request(buffer, MESSAGE_HASH_SEED_BYTES);  // R
  memcpy(buffer + MESSAGE_HASH_SEED_BYTES, tpk, CRYPTO_PUBLICKEYBYTES);
  while (!dma_done());

  msg_hash(m_h, buffer, smlen - CRYPTO_BYTES + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);

  dma_request(buffer, (TOTALTREE_HEIGHT+7)/8);  // retrieve leaf indices
  while (!dma_done());

  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++) {
    leafidx ^= (((unsigned long long)buffer[i]) << 8*i);
  }
#ifndef NOCOMMS // to be able to benchmark without communication
  if (horst_verify(root, tpk, m_h) != 0) {
    goto fail;
  }
#endif

  dma_request(buffer, WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES); while (!dma_done());
  for(i=0;i<N_LEVELS;i++)
  {
    if (i != N_LEVELS - 1)
      dma_request(buffer + ((1 - (i & 1)) * (WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES)), WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES);
    bufp = buffer + ((i & 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES));
    wots_verify(bufp, bufp, root, tpk);

    l_tree(pkhash, bufp,tpk);
    validate_authpath(root, pkhash, leafidx & 0x1f, bufp + WOTS_SIGBYTES, tpk, SUBTREE_HEIGHT);
    leafidx >>= 5;
    while (!dma_done());
  }

  for(i=0;i<HASH_BYTES;i++)
    if(root[i] != tpk[i+N_MASKS*HASH_BYTES])
      goto fail;
  
  return 0;
  
  
fail:
  for(i=0;i<*mlen;i++)
    m[i] = 0;
  *mlen = -1;
  return -1;
}

