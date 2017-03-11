#include "params.h"

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + CRYPTO_PUBLICKEYBYTES-HASH_BYTES + SK_RAND_SEED_BYTES) // 1088 B
#define CRYPTO_PUBLICKEYBYTES ((N_MASKS+1)*HASH_BYTES) // 1056 B
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + HORST_SIGBYTES + (TOTALTREE_HEIGHT/SUBTREE_HEIGHT)*WOTS_SIGBYTES + TOTALTREE_HEIGHT*HASH_BYTES)
// (32 + (60+7)/8 + 13312 + (60/5)*(67*32) + 60*32) = 41000
#define CRYPTO_DETERMINISTIC 1