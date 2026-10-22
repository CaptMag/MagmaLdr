#include "Salsa20.h"

/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* The implementation is based on:
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#define ROL(x,n) _rotl(x,n)

#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

int salsa20_done(salsa20_state* st)
{
    LTC_ARGCHK(st != NULL);
    RtlSecureZeroMemory(st, sizeof(salsa20_state));
    return CRYPT_OK;
}

int salsa20_memory(const unsigned char* key, unsigned long keylen, unsigned long rounds,
    const unsigned char* iv, unsigned long ivlen, ulong64 counter,
    const unsigned char* datain, unsigned long datalen, unsigned char* dataout)
{
    salsa20_state st;
    int err;

    if ((err = salsa20_setup(&st, key, keylen, rounds)) != CRYPT_OK) goto WIPE_KEY;
    if ((err = salsa20_ivctr64(&st, iv, ivlen, counter)) != CRYPT_OK) goto WIPE_KEY;
    err = salsa20_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
    salsa20_done(&st);
    return err;
}

int salsa20_ivctr64(salsa20_state* st, const unsigned char* iv, unsigned long ivlen, ulong64 counter)
{
    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(iv != NULL);
    /* Salsa20: 64-bit IV (nonce) + 64-bit counter */
    LTC_ARGCHK(ivlen == 8);

    LOAD32L(st->input[6], iv + 0);
    LOAD32L(st->input[7], iv + 4);
    st->input[8] = (ulong32)(counter & 0xFFFFFFFF);
    st->input[9] = (ulong32)(counter >> 32);
    st->ksleft = 0;
    st->ivlen = ivlen;
    return CRYPT_OK;
}



static void s_salsa20_block(unsigned char* output, const ulong32* input, int rounds)
{
    ulong32 x[16];
    int i;
    memcpy(x, input, sizeof(x));
    for (i = rounds; i > 0; i -= 2) {
        QUARTERROUND(0, 4, 8, 12)
            QUARTERROUND(5, 9, 13, 1)
            QUARTERROUND(10, 14, 2, 6)
            QUARTERROUND(15, 3, 7, 11)
            QUARTERROUND(0, 1, 2, 3)
            QUARTERROUND(5, 6, 7, 4)
            QUARTERROUND(10, 11, 8, 9)
            QUARTERROUND(15, 12, 13, 14)
    }
    for (i = 0; i < 16; ++i) {
        x[i] += input[i];
        STORE32L(x[i], output + 4 * i);
    }
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with Salsa20
   @param st      The Salsa20 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int salsa20_crypt(salsa20_state* st, const unsigned char* in, unsigned long inlen, unsigned char* out)
{
    unsigned char buf[64];
    unsigned long i, j;

    if (inlen == 0) return CRYPT_OK; /* nothing to do */

    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(in != NULL);
    LTC_ARGCHK(out != NULL);
    LTC_ARGCHK(st->ivlen == 8 || st->ivlen == 24);

    if (st->ksleft > 0) {
        j = MIN(st->ksleft, inlen);
        for (i = 0; i < j; ++i, st->ksleft--) out[i] = in[i] ^ st->kstream[64 - st->ksleft];
        inlen -= j;
        if (inlen == 0) return CRYPT_OK;
        out += j;
        in += j;
    }
    for (;;) {
        s_salsa20_block(buf, st->input, st->rounds);
        /* Salsa20: 64-bit IV, increment 64-bit counter */
        if (0 == ++st->input[8] && 0 == ++st->input[9]) return CRYPT_OVERFLOW;
        if (inlen <= 64) {
            for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
            st->ksleft = 64 - inlen;
            for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
            return CRYPT_OK;
        }
        for (i = 0; i < 64; ++i) out[i] = in[i] ^ buf[i];
        inlen -= 64;
        out += 64;
        in += 64;
    }
}

int salsa20_keystream(salsa20_state* st, unsigned char* out, unsigned long outlen)
{
    if (outlen == 0) return CRYPT_OK; /* nothing to do */
    LTC_ARGCHK(out != NULL);
    memset(out, 0, outlen);
    return salsa20_crypt(st, out, outlen, out);
}

int salsa20_setup(salsa20_state* st, const unsigned char* key, unsigned long keylen, int rounds)
{
    const char* const sigma = "expand 32-byte k";
    const char* const tau = "expand 16-byte k";
    const char* constants;

    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(key != NULL);
    LTC_ARGCHK(keylen == 32 || keylen == 16);

    if (rounds == 0) rounds = 20;
    LTC_ARGCHK(rounds % 2 == 0); /* number of rounds must be evenly divisible by 2 */

    LOAD32L(st->input[1], key + 0);
    LOAD32L(st->input[2], key + 4);
    LOAD32L(st->input[3], key + 8);
    LOAD32L(st->input[4], key + 12);
    if (keylen == 32) { /* 256bit */
        key += 16;
        constants = sigma;
    }
    else { /* 128bit */
        constants = tau;
    }
    LOAD32L(st->input[11], key + 0);
    LOAD32L(st->input[12], key + 4);
    LOAD32L(st->input[13], key + 8);
    LOAD32L(st->input[14], key + 12);
    LOAD32L(st->input[0], constants + 0);
    LOAD32L(st->input[5], constants + 4);
    LOAD32L(st->input[10], constants + 8);
    LOAD32L(st->input[15], constants + 12);
    st->rounds = rounds;     /* default is 20 for salsa20 */
    st->ivlen = 0;           /* will be set later by salsa20_ivctr(32|64) */
    return CRYPT_OK;
}