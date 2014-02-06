#ifndef TELEX_GCM_H
#define TELEX_GCM_H
#include <openssl/opensslconf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/modes.h>



// From crypto/modes/modes_lcl.h
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef __int64 i64;
typedef unsigned __int64 u64;
#define U64(C) C##UI64
#elif defined(__arch64__)
typedef long i64;
typedef unsigned long u64;
#define U64(C) C##UL
#else
typedef long long i64;
typedef unsigned long long u64;
#define U64(C) C##ULL
#endif

typedef unsigned int u32;
typedef unsigned char u8;

typedef struct { u64 hi,lo; } u128;
struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union { u64 u[2]; u32 d[4]; u8 c[16]; size_t t[16/sizeof(size_t)]; }
      Yi,EKi,EK0,len,Xi,H;
    /* Relative position of Xi, H and pre-computed Htable is used
     * in some assembler modules, i.e. don't change the order! */
    u128 Htable[16];
    void (*gmult)(u64 Xi[2],const u128 Htable[16]);
    void (*ghash)(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);
    unsigned int mres, ares;
    block128_f block;
    void *key;
};

// From crypto/evp/e_aes.c
typedef struct
    {
    AES_KEY ks;     /* AES key schedule to use */
    int key_set;        /* Set if key initialised */
    int iv_set;     /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;  /* Temporary IV store */
    int ivlen;      /* IV length */
    int taglen;
    int iv_gen;     /* It is OK to generate IVs */
    int tls_aad_len;    /* TLS AAD length */
    ctr128_f ctr;
    } EVP_AES_GCM_CTX;

#endif
