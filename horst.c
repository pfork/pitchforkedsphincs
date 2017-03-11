#include "params.h"
#include "horst.h"
#include "hash.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_stream_chacha20.h"
#include "chacha20/e/ref/e/ecrypt-sync.h"

void update_sig(const unsigned int *idxlist, const unsigned short *sigposlist, node *N, unsigned char* buf, unsigned short *boffset)
{
  int i;
  // not storing the top of auth paths; instead store layer 10
  if (N->idx >= 64 && N->idx < 128) {
    buf[*boffset] = ((N->idx-64)*HASH_BYTES) >> 8;
    *boffset += 1;
    buf[*boffset] = ((N->idx-64)*HASH_BYTES) & 0xff;
    *boffset += 1;
    memcpy(buf+*boffset, N->hash, HASH_BYTES);
    *boffset += HASH_BYTES;
  }
  else {
    for (i = 0; i < HORST_K * (HORST_LOGT-6); i++)
    {
      if (N->idx == idxlist[i]) {
        buf[*boffset] = sigposlist[i] >> 8;
        *boffset += 1;
        buf[*boffset] = sigposlist[i] & 0xff;
        *boffset += 1;
        memcpy(buf+*boffset, N->hash, HASH_BYTES);
        *boffset += HASH_BYTES;
      }
    }
  }
}

void update_sig_sk(const unsigned int *idxlist, const unsigned short *sigposlist, unsigned int idx, const unsigned char *sk, unsigned char* buf, unsigned short *boffset)
{
  int i;
  // the neighbor is in the auth path, not this node
  unsigned int neighbor = (idx&1)?idx-1:idx+1;
  for (i = 0; i < HORST_K * (HORST_LOGT-6); i++)
  {
    if (neighbor == idxlist[i]) {
      buf[*boffset] = (sigposlist[i] - HORST_SKBYTES) >> 8;
      *boffset += 1;
      buf[*boffset] = (sigposlist[i] - HORST_SKBYTES) & 0xff;
      *boffset += 1;
      memcpy(buf+*boffset, sk, HORST_SKBYTES);
      *boffset += HORST_SKBYTES;
    }
  }
}

void leafcalc(node *N, const unsigned char *sk, const unsigned int i)
{
  hash_n_n(N->hash, sk);
  N->idx = HORST_T+i;
  N->level = 0;
}

void treehash(const unsigned int *idxlist, const unsigned short *sigposlist,
              const unsigned char *sk,
              node *th_stack, int *stackptr, const unsigned int phi,
              const unsigned char masks[2*HORST_LOGT*HASH_BYTES],
              unsigned short indic, unsigned char* buf, unsigned short *boffset)
{
  unsigned char concat[HASH_BYTES*2];
  node N;
  leafcalc(&N, sk, phi);
  if (indic & 1) {
    update_sig_sk(idxlist, sigposlist, N.idx, sk, buf, boffset);
    update_sig(idxlist, sigposlist, &N, buf, boffset);
  }
  indic >>= 1;
  while (*stackptr >= 0 && N.level == th_stack[*stackptr].level)
  {
    memcpy(concat, th_stack[*stackptr].hash, HASH_BYTES);
    memcpy(concat+HASH_BYTES, N.hash, HASH_BYTES);
    hash_2n_n_mask(N.hash, concat, masks+2*N.level*HASH_BYTES);
    N.idx >>= 1;
    N.level = N.level + 1;
    *stackptr -= 1;
    if (indic & 1) {
      update_sig(idxlist, sigposlist, &N, buf, boffset);
    }
    indic >>= 1;
  }
  *stackptr += 1;
  memcpy(&th_stack[*stackptr], &N, sizeof(node));
}

int roundnumcmp(const void *p1, const void *p2) {
  unsigned short a = *(unsigned short*)p1;
  unsigned short b = *(unsigned short*)p2;
  return (a < b) ? -1 : (a > b);
}

void addtoroundnumlist(unsigned short *roundnumlist, unsigned short *roundnumpos,
                       const unsigned short indic, const unsigned short roundno) {
  int i;
  for (i = 0; i < *roundnumpos; i += 2) {
    if (roundnumlist[i] == roundno) {
      roundnumlist[i+1] |= indic;
      break;
    }
  }
  if (i == *roundnumpos) {
    roundnumlist[(*roundnumpos)++] = roundno;
    roundnumlist[(*roundnumpos)++] = indic;
  }
}

int horst_sign(unsigned char *sig,
               unsigned char pk[HASH_BYTES],
               const unsigned char seed[SEED_BYTES],
               const unsigned char masks[2*HORST_LOGT*HASH_BYTES],
               const unsigned char m_hash[MSGHASH_BYTES])
{
  #if HORST_SKBYTES != HASH_BYTES
  #error "Need to have HORST_SKBYTES == HASH_BYTES"
  #endif
  #if HORST_K != (MSGHASH_BYTES/2)
  #error "Need to have HORST_K == (MSGHASH_BYTES/2)"
  #endif

  unsigned int idx; // one-based, root node has idx = 1
  int i, j;
  unsigned short sigpos = 0;
  unsigned short idxlistpos = 0;
  unsigned short roundnumpos = 0;
  unsigned short indic;
  unsigned short roundno;
  unsigned int idxlist[HORST_K * (HORST_LOGT-6)];
  unsigned short sigposlist[HORST_K * (HORST_LOGT-6)];
  unsigned short roundnumlist[2*HORST_K * (HORST_LOGT-6+1)]; // alternates roundnum and indicator bits, +1 for sk
  node th_stack[HORST_LOGT * 2];
  
  // initialise idx list to zeros to prevent erroneous matches
  for (i=0; i < HORST_K * (HORST_LOGT-6); i++)
  {
    idxlist[i] = 0;
  }
  // same for roundnumlist
  for (i=0; i < 2*HORST_K * (HORST_LOGT-6); i++)
  {
    roundnumlist[i] = 0;
  }

  ECRYPT_ctx x;
  crypto_stream_chacha20_setup(&x, 0, seed);

  sigpos += 64*HASH_BYTES; // reserve room for 64 hashes of level 10

  // Precompute the indices of the auth-path hashes
  // computes the secret key parts and puts those in the right place
  // Signature consists of HORST_K parts; each part of secret key and HORST_LOGT-6 auth-path hashes
  for(i=0;i<HORST_K;i++)
  {
    idx = m_hash[2*i] + (m_hash[2*i+1]<<8);
    sigpos += HORST_SKBYTES;
    roundno = idx;
    idx += (HORST_T);
    indic = 1;
    addtoroundnumlist(roundnumlist, &roundnumpos, indic, roundno);
    for(j=0;j<HORST_LOGT-6;j++)
    {
      // get neighbor round number
      roundno += ((idx&1)? -(1<<j) : 1<<j);
      addtoroundnumlist(roundnumlist, &roundnumpos, indic, roundno);
      idx = (idx&1)?idx-1:idx+1; // neighbor node
      idxlist[idxlistpos] = idx;
      sigposlist[idxlistpos] = sigpos;
      idxlistpos++;
      sigpos += HASH_BYTES;
      if ((idx&1) == 0) {
        roundno += 1<<j;
      }
      indic <<= 1;
      idx >>= 1; // parent node
    }
  }

  qsort(roundnumlist, roundnumpos/2, 2*sizeof(unsigned short), roundnumcmp);

  roundnumpos = 0;
  int stackptr = -1;

  unsigned char sk[64];
  unsigned char buf[HASH_BYTES*(HORST_LOGT-5)];
  unsigned short boffset = 0;
  for (i=0; i < HORST_T; i++) //generate leafs for the pubkeys along the bottom
  {
    if ((i&1) == 0) {
      crypto_stream_chacha20_64b(&x, sk);
    }
    indic = 0x0400; // always store layer 6
    if (roundnumlist[roundnumpos] == i) {
      indic |= roundnumlist[roundnumpos+1];
      roundnumpos += 2;
    }
    treehash(idxlist, sigposlist, sk + (i&1)*HORST_SKBYTES, th_stack, &stackptr, i, masks, indic, buf, &boffset);
    unsigned int i2;
    unsigned short pos2;
    for(i2=0;i2<boffset;) {
      pos2=(buf[i2] << 8) | buf[i2+1];
      memcpy(sig+pos2, buf+i2+2, HASH_BYTES);
      i2+=HASH_BYTES+2;
      if(i2<HASH_BYTES+2 && i2>0) {
      }
    }
    boffset=0;
  }

  for(i=0;i<HASH_BYTES;i++)
    pk[i] = th_stack[0].hash[i];

  return 0;
}

int horst_verify(unsigned char* sig,
                 unsigned char *pk,
                 const unsigned char masks[2*HORST_LOGT*HASH_BYTES],
                 const unsigned char m_hash[MSGHASH_BYTES])
{
  //unsigned char buffer[HASH_BYTES*(HORST_LOGT-6+1) * 2];
  unsigned char *buffer = sig + (64 * HASH_BYTES);
  unsigned char *l, *r, *bufp, *bufstart;
  unsigned char hashbuf[HASH_BYTES];
  //unsigned char level10[64*HASH_BYTES];
  unsigned char *level10 = sig;
  unsigned int idx;
  int i,j,k;

#if HORST_K != (MSGHASH_BYTES/2)
#error "Need to have HORST_K == (MSGHASH_BYTES/2)"
#endif

  //dma_request(level10, 64*HASH_BYTES);
  //dma_request(buffer, HASH_BYTES*(HORST_LOGT-6+1));

  for(i=0;i<HORST_K;i++)
  {
    //if (i != 31)
    //  dma_request(buffer + HASH_BYTES*(HORST_LOGT-6+1) * (1 - (i & 1)), HASH_BYTES*(HORST_LOGT-6+1));
    bufstart = buffer;
    idx = m_hash[2*i] + (m_hash[2*i+1]<<8);

#if HORST_SKBYTES != HASH_BYTES
#error "Need to have HORST_SKBYTES == HASH_BYTES"
#endif

    hash_n_n(bufstart,bufstart);
    if(!(idx&1))
    {
      l = bufstart;
      r = bufstart+HASH_BYTES;
    }
    else
    {
      l = bufstart+HASH_BYTES;
      r = bufstart;
    }
    bufp = bufstart + 2*HASH_BYTES;

    for(k=1;k<HORST_LOGT-6;k++)
    {
      idx = idx>>1; // parent node

      if(!(idx&1))
      {
        hash_nn_n_mask(hashbuf, l, r,masks+2*(k-1)*HASH_BYTES);
        l = hashbuf;
        r = bufp;
      }
      else
      {
        hash_nn_n_mask(hashbuf,l, r,masks+2*(k-1)*HASH_BYTES);
        l = bufp;
        r = hashbuf;
      }
      bufp += HASH_BYTES;
    }

    idx = idx>>1; // parent node
    hash_nn_n_mask(bufstart,l, r,masks+2*(HORST_LOGT-7)*HASH_BYTES);

    for(k=0;k<HASH_BYTES;k++)
      if(level10[idx*HASH_BYTES+k] != bufstart[k]) {
        goto fail;
      }
    buffer += HASH_BYTES*(HORST_LOGT-6+1);
  }

  // Compute root from level10
  for(j=0;j<32;j++)
    hash_2n_n_mask(level10+j*HASH_BYTES, level10+2*j*HASH_BYTES, masks+2*(HORST_LOGT-6)*HASH_BYTES);
  // Hash from level 11 to 12
  for(j=0;j<16;j++)
    hash_2n_n_mask(level10+j*HASH_BYTES,level10+2*j*HASH_BYTES,masks+2*(HORST_LOGT-5)*HASH_BYTES);
  // Hash from level 12 to 13
  for(j=0;j<8;j++)
    hash_2n_n_mask(level10+j*HASH_BYTES,level10+2*j*HASH_BYTES,masks+2*(HORST_LOGT-4)*HASH_BYTES);
  // Hash from level 13 to 14
  for(j=0;j<4;j++)
    hash_2n_n_mask(level10+j*HASH_BYTES,level10+2*j*HASH_BYTES,masks+2*(HORST_LOGT-3)*HASH_BYTES);
  // Hash from level 14 to 15
  for(j=0;j<2;j++)
    hash_2n_n_mask(level10+j*HASH_BYTES,level10+2*j*HASH_BYTES,masks+2*(HORST_LOGT-2)*HASH_BYTES);
  // Hash from level 15 to 16
  hash_2n_n_mask(pk, level10, masks+2*(HORST_LOGT-1)*HASH_BYTES);

  return 0;


fail:
  for(k=0;k<HASH_BYTES;k++)
    pk[k] = 0;
  return -1;
}
