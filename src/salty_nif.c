/**
 * Copyright 2017 Jan van de Molengraft <jan@artemisc.eu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <string.h>
#include "sodium.h"
#include "erl_nif.h"

/*******************************************************************************
 *
 * IMPORTANT NOTE
 *
 * The following macros require that every method using them defines its
 * arguments using the same names.
 *
 * (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
 *
 ******************************************************************************/

/* SALTY_MAX_CLEAN_SIZE is the maximum amount of bytes a nif call can process
 * before we should consider invoking the dirty schedulers.
 *
 * TODO validate this number, and use it.
 * TODO can dirty schedulers be called at runtime?
 */
#define SALTY_MAX_CLEAN_SIZE (16 * 1024)

#define SALTY_NOERR 0
#define SALTY_BADARG enif_make_badarg(env)
#define SALTY_BADALLOC SALTY_BADARG /* TODO make this return an actual failed-to-alloc error */

#define SALTY_ERROR tuple_error_unknown
#define SALTY_ERROR_PAIR(err) enif_make_tuple2(env, atom_error, err)
#define SALTY_OK atom_ok
#define SALTY_OK_PAIR(a) enif_make_tuple2(env, atom_ok, a)
#define SALTY_OK_TRIPLET(a, b) enif_make_tuple3(env, atom_ok, a, b)

#define SALTY_BIN_NO_SIZE 0
/*#define SALTY_FORCE_BOUNDS(val, lower, upper)                                   \
    if (val < lower || val > upper) {                                           \
        return (SALTY_BADARG);                                                  \
    }*/
#define SALTY_INPUT_UINT64(index, dst)                                          \
    ErlNifUInt64 dst;                                                           \
    if (!enif_get_uint64(env, argv[index], &dst)) {                             \
        return (SALTY_BADARG);                                                  \
    }

#define SALTY_INPUT_BIN(index, dst, len)                                        \
    ErlNifBinary dst;                                                           \
    if (!enif_inspect_binary(env, argv[index], &dst)) {                         \
        if (!enif_inspect_iolist_as_binary(env, argv[index], &dst)) {           \
            return (SALTY_BADARG);                                              \
        }                                                                       \
    }                                                                           \
    if (dst.size < len) {                                                       \
        return (SALTY_BADARG);                                                  \
    }

/* TODO implement this macro */
#define SALTY_INPUT_RES(index, dst) \
    ErlNifResourceType

#define SALTY_OUTPUT_BIN(dst, len)                                              \
    ErlNifBinary dst;                                                           \
    if (!enif_alloc_binary(len, &dst)) {                                        \
        return (SALTY_BADALLOC);                                                \
    }

#define OUT(a) enif_make_binary(env, &a)
#define SALTY_FUNC(name, args)                                                  \
    static ERL_NIF_TERM                                                         \
    salty_##name (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {        \
        if (argc != args) {                                                     \
            return (SALTY_BADARG);                                              \
        }
#define DO
#define END }
#define END_OK return (SALTY_OK); END
#define END_OK_WITH(out) return (SALTY_OK_PAIR(OUT(out))); END
#define END_OK_WITH2(a, b) return (SALTY_OK_TRIPLET(OUT(a), OUT(b))); END

#define SALTY_CONST_INT64(constant)                                             \
    static ERL_NIF_TERM                                                         \
    salty_##constant (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {    \
        return enif_make_uint64(env, crypto_##constant);                        \
    }
#define SALTY_CONST_INT64_NOPREFIX(constant)                                    \
    static ERL_NIF_TERM                                                         \
    salty_##constant (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {    \
        return enif_make_uint64(env, constant);                                 \
    }

#define SALTY_EXPORT_NAME(name) #name
#define SALTY_EXPORT_CONS(name, args) { SALTY_EXPORT_NAME(name), args, salty_##name }
#define SALTY_EXPORT_FUNC(name, args) { SALTY_EXPORT_NAME(name), args, salty_##name }
#define SALTY_EXPORT_FUNC_DIRTY(name, args) { SALTY_EXPORT_NAME(name), args, salty_##name, ERL_NIF_DIRTY_JOB_CPU_BOUND }

#define SALTY_CALL_SIMPLE(call)                                                 \
    if (( call ) != SALTY_NOERR) {                                              \
        return (SALTY_ERROR);                                                   \
    }

#define SALTY_CALL_SIMPLE_WITHERR(call, error)                                  \
    if (( call ) != SALTY_NOERR) {                                              \
        return (SALTY_ERROR_PAIR(error));                                       \
    }

#define SALTY_CALL(call, output)                                                \
    if (( call ) != SALTY_NOERR) {                                              \
        enif_release_binary(&output);                                           \
        return (SALTY_ERROR);                                                   \
    }

#define SALTY_CALL2(call, outputa, outputb)                                     \
    if (( call ) != SALTY_NOERR) {                                              \
        enif_release_binary(&outputa);                                          \
        enif_release_binary(&outputb);                                          \
        return (SALTY_ERROR);                                                   \
    }

#define SALTY_CALL_WITHERR(call, error, output)                                 \
    if (( call ) != SALTY_NOERR) {                                              \
        enif_release_binary(&output);                                           \
        return (SALTY_ERROR_PAIR(error));                                       \
    }

/**
 * !FIX for randombytes_SEEDBYTES
 */
#define crypto_randombytes_SEEDBYTES randombytes_seedbytes()
#undef randombytes_SEEDBYTES

/**
 * Additional self-defined constants that are missing but required
 */
#define crypto_box_curve25519xchacha20poly1305_SEALBYTES (crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xchacha20poly1305_MACBYTES)
#define crypto_box_curve25519xsalsa20poly1305_SEALBYTES (crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES)

/**
 * Additional self defined functions to make writing bindings easier. These are
 * all based on code found in libsodium's source.
 */
int
crypto_auth_hmacsha256_final_verify(crypto_auth_hmacsha256_state *state,
                                    const unsigned char          *h) {
    unsigned char correct[32];

    crypto_auth_hmacsha256_final(state, correct);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 32);
}

int
crypto_auth_hmacsha512_final_verify(crypto_auth_hmacsha512_state *state,
                                    const unsigned char          *h) {
    unsigned char correct[64];

    crypto_auth_hmacsha512_final(state, correct);

    return crypto_verify_64(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 64);
}

int
crypto_auth_hmacsha512256_final_verify(crypto_auth_hmacsha512256_state *state,
                                       const unsigned char             *h) {
    unsigned char correct[32];

    crypto_auth_hmacsha512256_final(state, correct);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 32);
}

static int
_crypto_box_curve25519xchacha20poly1305_seal_nonce(unsigned char       *nonce,
                                                   const unsigned char *pk1,
                                                   const unsigned char *pk2) {
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
    crypto_generichash_update(&st, pk1, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_update(&st, pk2, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);

    return 0;
}

int
crypto_box_curve25519xchacha20poly1305_seal(unsigned char       *c,
                                            const unsigned char *m,
                                            unsigned long long  mlen,
                                            const unsigned char *pk) {
    unsigned char nonce[crypto_box_curve25519xchacha20poly1305_NONCEBYTES];
    unsigned char epk[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
    unsigned char esk[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    int           ret;

    if (crypto_box_curve25519xchacha20poly1305_keypair(epk, esk) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    memcpy(c, epk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    _crypto_box_curve25519xchacha20poly1305_seal_nonce(nonce, epk, pk);
    ret = crypto_box_easy(c + crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
                          m, mlen, nonce, pk, esk);
    sodium_memzero(esk, sizeof esk);
    sodium_memzero(epk, sizeof epk);
    sodium_memzero(nonce, sizeof nonce);

    return ret;
}

int
crypto_box_curve25519xchacha20poly1305_seal_open(unsigned char       *m,
                                                 const unsigned char *c,
                                                 unsigned long long  clen,
                                                 const unsigned char *pk,
                                                 const unsigned char *sk) {
    unsigned char nonce[crypto_box_curve25519xchacha20poly1305_NONCEBYTES];

    if (clen < crypto_box_curve25519xchacha20poly1305_SEALBYTES) {
        return -1;
    }
    _crypto_box_curve25519xchacha20poly1305_seal_nonce(nonce, c, pk);

    /*COMPILER_ASSERT(crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES < crypto_box_curve25519xchacha20poly1305_SEALBYTES);*/
    return crypto_box_open_easy(m, c + crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
                                clen - crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
                                nonce, c, sk);
}

int
crypto_box_curve25519xsalsa20poly1305_easy(unsigned char       *c,
                                           const unsigned char *m,
                                           unsigned long long  mlen,
                                           const unsigned char *n,
                                           const unsigned char *pk,
                                           const unsigned char *sk) {
    return crypto_box_easy(c, m, mlen, n, pk, sk);
}

int
crypto_box_curve25519xsalsa20poly1305_detached(unsigned char       *c,
                                               unsigned char       *mac,
                                               const unsigned char *m,
                                               unsigned long long  mlen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk) {
    return crypto_box_detached(c, mac, m, mlen, n, pk, sk);
}

int
crypto_box_curve25519xsalsa20poly1305_open_detached(unsigned char       *m,
                                                    const unsigned char *c,
                                                    const unsigned char *mac,
                                                    unsigned long long  clen,
                                                    const unsigned char *n,
                                                    const unsigned char *pk,
                                                    const unsigned char *sk) {
    return crypto_box_open_detached(m, c, mac, clen, n, pk, sk);
}

int
crypto_box_curve25519xsalsa20poly1305_easy_afternm(unsigned char       *c,
                                                   const unsigned char *m,
                                                   unsigned long long  mlen,
                                                   const unsigned char *n,
                                                   const unsigned char *k) {
    return crypto_box_easy_afternm(c, m, mlen, n, k);
}

int
crypto_box_curve25519xsalsa20poly1305_detached_afternm(unsigned char       *c,
                                                       unsigned char       *mac,
                                                       const unsigned char *m,
                                                       unsigned long long  mlen,
                                                       const unsigned char *n,
                                                       const unsigned char *k) {
    return crypto_box_detached_afternm(c, mac, m, mlen, n, k);
}

int
crypto_box_curve25519xsalsa20poly1305_open_detached_afternm(unsigned char       *m,
                                                            const unsigned char *c,
                                                            const unsigned char *mac,
                                                            unsigned long long  clen,
                                                            const unsigned char *n,
                                                            const unsigned char *k) {
    return crypto_box_open_detached_afternm(m, c, mac, clen, n, k);
}


int
crypto_box_curve25519xsalsa20poly1305_seal(unsigned char       *c,
                                           const unsigned char *m,
                                           unsigned long long  mlen,
                                           const unsigned char *pk) {
    return crypto_box_seal(c, m, mlen, pk);
}

int
crypto_box_curve25519xsalsa20poly1305_seal_open(unsigned char       *m,
                                                const unsigned char *c,
                                                unsigned long long  clen,
                                                const unsigned char *pk,
                                                const unsigned char *sk) {
    return crypto_box_seal_open(m, c, clen, pk, sk);
}

int
crypto_hash_sha256_verify(const unsigned char *h,
                          const unsigned char *in,
                          unsigned long long  inlen) {
    unsigned char correct[32];

    crypto_hash_sha256(correct, in, inlen);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 32);
}

int
crypto_hash_sha256_final_verify(crypto_hash_sha256_state *state,
                                const unsigned char      *h) {
    unsigned char correct[32];

    crypto_hash_sha256_final(state, correct);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 32);
}

int
crypto_hash_sha512_verify(const unsigned char *h,
                          const unsigned char *in,
                          unsigned long long  inlen) {
    unsigned char correct[64];

    crypto_hash_sha512(correct, in, inlen);

    return crypto_verify_64(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 64);
}

int
crypto_hash_sha512_final_verify(crypto_hash_sha512_state *state,
                                const unsigned char      *h) {
    unsigned char correct[64];

    crypto_hash_sha512_final(state, correct);

    return crypto_verify_64(h, correct) | (-(h == correct)) |
           sodium_memcmp(correct, h, 64);
}

int
crypto_onetimeauth_poly1305_final_verify(crypto_onetimeauth_poly1305_state *state,
                                         const unsigned char               *h) {
    unsigned char correct[16];

    crypto_onetimeauth_poly1305_final(state, correct);

    return crypto_verify_16(h, correct);
}

int
crypto_secretbox_xsalsa20poly1305_easy(unsigned char       *c,
                                       const unsigned char *m,
                                       unsigned long long  mlen,
                                       const unsigned char *n,
                                       const unsigned char *k) {
    return crypto_secretbox_easy(c, m, mlen, n, k);
}

int
crypto_secretbox_xsalsa20poly1305_detached(unsigned char       *c,
                                           unsigned char       *mac,
                                           const unsigned char *m,
                                           unsigned long long  mlen,
                                           const unsigned char *n,
                                           const unsigned char *k) {
    return crypto_secretbox_detached(c, mac, m, mlen, n, k);
}

int
crypto_secretbox_xsalsa20poly1305_open_detached(unsigned char       *m,
                                                const unsigned char *c,
                                                const unsigned char *mac,
                                                unsigned long long  clen,
                                                const unsigned char *n,
                                                const unsigned char *k) {
    return crypto_secretbox_open_detached(m, c, mac, clen, n, k);
}

/* STATIC VALUES */
ERL_NIF_TERM atom_ok;
ERL_NIF_TERM atom_error;
ERL_NIF_TERM atom_error_no_match;
ERL_NIF_TERM atom_error_not_available;
ERL_NIF_TERM atom_error_forged;
ERL_NIF_TERM atom_error_unknown;
ERL_NIF_TERM tuple_error_unknown;

/*
TODO is useful to create this through the nif code?
ERL_NIF_TERM atom_primitive_auth;
ERL_NIF_TERM atom_primitive_box;
ERL_NIF_TERM atom_primitive_secretbox;
ERL_NIF_TERM atom_primitive_sign;*/

/* erl_nif code */
static int
salty_onload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    /* register the safe resource types for keys and private data */
    
    /* cache atom values */
    atom_ok                  = enif_make_atom(env, "ok");
    atom_error               = enif_make_atom(env, "error");
    atom_error_no_match      = enif_make_atom(env, "no_match");
    atom_error_not_available = enif_make_atom(env, "not_available");
    atom_error_forged        = enif_make_atom(env, "forged");
    atom_error_unknown       = enif_make_atom(env, "salty_error_unknown");
    tuple_error_unknown      = enif_make_tuple2(env, atom_error, atom_error_unknown);

    return 0;
}

/**
 * Sodium internal
 */

/* sodium_init */
SALTY_FUNC(init, 0) DO
    SALTY_CALL_SIMPLE(sodium_init());
END_OK;

/* sodium_memcmp */
SALTY_FUNC(memcmp, 2) DO
    SALTY_INPUT_BIN(0, a, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, b, SALTY_BIN_NO_SIZE);

    if (a.size != b.size) {
        return (SALTY_ERROR);
    }

    SALTY_CALL_SIMPLE(sodium_memcmp(a.data, b.data, a.size));
END_OK;

/* safe key-gen (using locked memory binary resource) */

/**
 * AEAD aes256gcm
 */
SALTY_CONST_INT64(aead_aes256gcm_KEYBYTES);
SALTY_CONST_INT64(aead_aes256gcm_NSECBYTES);
SALTY_CONST_INT64(aead_aes256gcm_NPUBBYTES);
SALTY_CONST_INT64(aead_aes256gcm_ABYTES);

SALTY_FUNC(aead_aes256gcm_is_available, 0) DO
    if (crypto_aead_aes256gcm_is_available() == 0) {
        return (SALTY_ERROR_PAIR(atom_error_not_available));
    }
END_OK;

SALTY_FUNC(aead_aes256gcm_encrypt, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_aes256gcm_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_aes256gcm_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_aes256gcm_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_aead_aes256gcm_ABYTES + plain.size);

    SALTY_CALL(crypto_aead_aes256gcm_encrypt(
                cipher.data, NULL, plain.data, plain.size, ad.data, ad.size,
                NULL, npub.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(aead_aes256gcm_encrypt_detached, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_aes256gcm_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_aes256gcm_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_aes256gcm_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, plain.size);
    SALTY_OUTPUT_BIN(mac, crypto_aead_aes256gcm_ABYTES);

    SALTY_CALL2(crypto_aead_aes256gcm_encrypt_detached(
                cipher.data, mac.data, NULL, plain.data, plain.size, ad.data,
                ad.size, NULL, npub.data, key.data), cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(aead_aes256gcm_decrypt_detached, 6) DO
    /*SALTY_INPUT_BIN(0, nsec,   crypto_aead_aes256gcm_NSECBYTES);*/
    SALTY_INPUT_BIN(1, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, mac,    crypto_aead_aes256gcm_ABYTES);
    SALTY_INPUT_BIN(3, ad,     SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(4, npub,   crypto_aead_aes256gcm_NPUBBYTES);
    SALTY_INPUT_BIN(5, key,    crypto_aead_aes256gcm_KEYBYTES);

    SALTY_OUTPUT_BIN(plain, cipher.size);

    SALTY_CALL_WITHERR(crypto_aead_aes256gcm_decrypt_detached(
                plain.data, NULL, cipher.data, cipher.size, mac.data,
                ad.data, ad.size, npub.data, key.data),
                atom_error_forged, plain);
END_OK_WITH(plain);

/**
 * AEAD chacha20poly1305
 */
SALTY_CONST_INT64(aead_chacha20poly1305_KEYBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_NSECBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_NPUBBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_ABYTES);

SALTY_FUNC(aead_chacha20poly1305_encrypt, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_chacha20poly1305_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_chacha20poly1305_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_chacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_aead_chacha20poly1305_ABYTES + plain.size);

    SALTY_CALL(crypto_aead_chacha20poly1305_encrypt(
                cipher.data, NULL, plain.data, plain.size, ad.data, ad.size,
                NULL, npub.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(aead_chacha20poly1305_encrypt_detached, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_chacha20poly1305_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_chacha20poly1305_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_chacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, plain.size);
    SALTY_OUTPUT_BIN(mac, crypto_aead_chacha20poly1305_ABYTES);

    SALTY_CALL2(crypto_aead_chacha20poly1305_encrypt_detached(
                cipher.data, mac.data, NULL, plain.data, plain.size, ad.data,
                ad.size, NULL, npub.data, key.data), cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(aead_chacha20poly1305_decrypt_detached, 6) DO
    /*SALTY_INPUT_BIN(0, nsec,   crypto_aead_chacha20poly1305_NSECBYTES);*/
    SALTY_INPUT_BIN(1, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, mac,    crypto_aead_chacha20poly1305_ABYTES);
    SALTY_INPUT_BIN(3, ad,     SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(4, npub,   crypto_aead_chacha20poly1305_NPUBBYTES);
    SALTY_INPUT_BIN(5, key,    crypto_aead_chacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(plain, cipher.size);

    SALTY_CALL_WITHERR(crypto_aead_chacha20poly1305_decrypt_detached(
                plain.data, NULL, cipher.data, cipher.size, mac.data,
                ad.data, ad.size, npub.data, key.data),
                atom_error_forged, plain);
END_OK_WITH(plain);

/**
 * AEAD chacha20poly1305_ietf
 */
SALTY_CONST_INT64(aead_chacha20poly1305_ietf_KEYBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_ietf_NSECBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_ietf_NPUBBYTES);
SALTY_CONST_INT64(aead_chacha20poly1305_ietf_ABYTES);

SALTY_FUNC(aead_chacha20poly1305_ietf_encrypt, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_chacha20poly1305_ietf_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_aead_chacha20poly1305_ietf_ABYTES + plain.size);

    SALTY_CALL(crypto_aead_chacha20poly1305_ietf_encrypt(
                cipher.data, NULL, plain.data, plain.size, ad.data, ad.size,
                NULL, npub.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(aead_chacha20poly1305_ietf_encrypt_detached, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_chacha20poly1305_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, plain.size);
    SALTY_OUTPUT_BIN(mac, crypto_aead_chacha20poly1305_ietf_ABYTES);

    SALTY_CALL2(crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                cipher.data, mac.data, NULL, plain.data, plain.size, ad.data,
                ad.size, NULL, npub.data, key.data), cipher, mac);
END_OK_WITH2(cipher, mac);


SALTY_FUNC(aead_chacha20poly1305_ietf_decrypt_detached, 6) DO
    /*SALTY_INPUT_BIN(0, nsec,   crypto_aead_chacha20poly1305_ietf_NSECBYTES);*/
    SALTY_INPUT_BIN(1, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, mac,    crypto_aead_chacha20poly1305_ietf_ABYTES);
    SALTY_INPUT_BIN(3, ad,     SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(4, npub,   crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(5, key,    crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(plain, cipher.size);

    SALTY_CALL_WITHERR(crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                plain.data, NULL, cipher.data, cipher.size, mac.data,
                ad.data, ad.size, npub.data, key.data),
                atom_error_forged, plain);
END_OK_WITH(plain);

/**
 * AEAD xchacha20poly1305_ietf
 */
SALTY_CONST_INT64(aead_xchacha20poly1305_ietf_KEYBYTES);
SALTY_CONST_INT64(aead_xchacha20poly1305_ietf_NSECBYTES);
SALTY_CONST_INT64(aead_xchacha20poly1305_ietf_NPUBBYTES);
SALTY_CONST_INT64(aead_xchacha20poly1305_ietf_ABYTES);

SALTY_FUNC(aead_xchacha20poly1305_ietf_encrypt, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_xchacha20poly1305_ietf_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_aead_xchacha20poly1305_ietf_ABYTES + plain.size);

    SALTY_CALL(crypto_aead_xchacha20poly1305_ietf_encrypt(
                cipher.data, NULL, plain.data, plain.size, ad.data, ad.size,
                NULL, npub.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(aead_xchacha20poly1305_ietf_encrypt_detached, 5) DO
    SALTY_INPUT_BIN(0, plain, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, ad,    SALTY_BIN_NO_SIZE);
    /*SALTY_INPUT_BIN(2, nsec,  crypto_aead_xchacha20poly1305_NSECBYTES);*/
    SALTY_INPUT_BIN(3, npub,  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(4, key,   crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, plain.size);
    SALTY_OUTPUT_BIN(mac, crypto_aead_xchacha20poly1305_ietf_ABYTES);

    SALTY_CALL2(crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                cipher.data, mac.data, NULL, plain.data, plain.size, ad.data,
                ad.size, NULL, npub.data, key.data), cipher, mac);
END_OK_WITH2(cipher, mac);


SALTY_FUNC(aead_xchacha20poly1305_ietf_decrypt_detached, 6) DO
    /*SALTY_INPUT_BIN(0, nsec,   crypto_aead_xchacha20poly1305_ietf_NSECBYTES);*/
    SALTY_INPUT_BIN(1, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, mac,    crypto_aead_xchacha20poly1305_ietf_ABYTES);
    SALTY_INPUT_BIN(3, ad,     SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(4, npub,   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    SALTY_INPUT_BIN(5, key,    crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    SALTY_OUTPUT_BIN(plain, cipher.size);

    SALTY_CALL_WITHERR(crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                plain.data, NULL, cipher.data, cipher.size, mac.data,
                ad.data, ad.size, npub.data, key.data),
                atom_error_forged, plain);
END_OK_WITH(plain);

/**
 * AUTH hmacsha256
 */
SALTY_CONST_INT64(auth_hmacsha256_BYTES);
SALTY_CONST_INT64(auth_hmacsha256_KEYBYTES);

SALTY_FUNC(auth_hmacsha256, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_auth_hmacsha256_KEYBYTES);

    SALTY_OUTPUT_BIN(mac, crypto_auth_hmacsha256_BYTES);

    SALTY_CALL(crypto_auth_hmacsha256(mac.data, msg.data, msg.size, key.data), mac);
END_OK_WITH(mac);

SALTY_FUNC(auth_hmacsha256_verify, 3) DO
    SALTY_INPUT_BIN(0, mac, crypto_auth_hmacsha256_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_auth_hmacsha256_KEYBYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha256_verify(
                mac.data, msg.data, msg.size, key.data),
            atom_error_no_match);
END_OK;

SALTY_FUNC(auth_hmacsha256_init, 1) DO
    SALTY_INPUT_BIN(0, key, SALTY_BIN_NO_SIZE);

    SALTY_OUTPUT_BIN(state, crypto_auth_hmacsha256_statebytes());

    SALTY_CALL(crypto_auth_hmacsha256_init(
                (crypto_auth_hmacsha256_state *) state.data,
                key.data, key.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha256_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha256_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_auth_hmacsha256_update(
                (crypto_auth_hmacsha256_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha256_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha256_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_auth_hmacsha256_BYTES);

    SALTY_CALL(crypto_auth_hmacsha256_final(
                (crypto_auth_hmacsha256_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(auth_hmacsha256_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha256_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_auth_hmacsha256_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha256_final_verify(
                (crypto_auth_hmacsha256_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * AUTH hmacsha512
 */
SALTY_CONST_INT64(auth_hmacsha512_BYTES);
SALTY_CONST_INT64(auth_hmacsha512_KEYBYTES);

SALTY_FUNC(auth_hmacsha512, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_auth_hmacsha512_KEYBYTES);

    SALTY_OUTPUT_BIN(mac, crypto_auth_hmacsha512_BYTES);

    SALTY_CALL(crypto_auth_hmacsha512(mac.data, msg.data, msg.size, key.data), mac);
END_OK_WITH(mac);

SALTY_FUNC(auth_hmacsha512_verify, 3) DO
    SALTY_INPUT_BIN(0, mac, crypto_auth_hmacsha512_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_auth_hmacsha512_KEYBYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha512_verify(
                mac.data, msg.data, msg.size, key.data),
            atom_error_no_match);
END_OK;

SALTY_FUNC(auth_hmacsha512_init, 1) DO
    SALTY_INPUT_BIN(0, key, SALTY_BIN_NO_SIZE);

    SALTY_OUTPUT_BIN(state, crypto_auth_hmacsha512_statebytes());

    SALTY_CALL(crypto_auth_hmacsha512_init(
                (crypto_auth_hmacsha512_state *) state.data,
                key.data, key.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha512_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_auth_hmacsha512_update(
                (crypto_auth_hmacsha512_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha512_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_auth_hmacsha512_BYTES);

    SALTY_CALL(crypto_auth_hmacsha512_final(
                (crypto_auth_hmacsha512_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(auth_hmacsha512_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_auth_hmacsha512_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha512_final_verify(
                (crypto_auth_hmacsha512_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * AUTH hmacsha512256
 */
SALTY_CONST_INT64(auth_hmacsha512256_BYTES);
SALTY_CONST_INT64(auth_hmacsha512256_KEYBYTES);

SALTY_FUNC(auth_hmacsha512256, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_auth_hmacsha512256_KEYBYTES);

    SALTY_OUTPUT_BIN(mac, crypto_auth_hmacsha512256_BYTES);

    SALTY_CALL(crypto_auth_hmacsha512256(mac.data, msg.data, msg.size, key.data), mac);
END_OK_WITH(mac);

SALTY_FUNC(auth_hmacsha512256_verify, 3) DO
    SALTY_INPUT_BIN(0, mac, crypto_auth_hmacsha512256_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_auth_hmacsha512256_KEYBYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha512256_verify(
                mac.data, msg.data, msg.size, key.data),
            atom_error_no_match);
END_OK;

SALTY_FUNC(auth_hmacsha512256_init, 1) DO
    SALTY_INPUT_BIN(0, key, SALTY_BIN_NO_SIZE);

    SALTY_OUTPUT_BIN(state, crypto_auth_hmacsha512256_statebytes());

    SALTY_CALL(crypto_auth_hmacsha512256_init(
                (crypto_auth_hmacsha512256_state *) state.data,
                key.data, key.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha512256_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512256_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_auth_hmacsha512256_update(
                (crypto_auth_hmacsha512256_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(auth_hmacsha512256_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512256_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_auth_hmacsha512256_BYTES);

    SALTY_CALL(crypto_auth_hmacsha512256_final(
                (crypto_auth_hmacsha512256_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(auth_hmacsha512256_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_auth_hmacsha512256_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_auth_hmacsha512256_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_auth_hmacsha512256_final_verify(
                (crypto_auth_hmacsha512256_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * BOX curve25519xchacha20poly1305
 */
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_SEEDBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_SECRETKEYBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_BEFORENMBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_NONCEBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_MACBYTES);
SALTY_CONST_INT64(box_curve25519xchacha20poly1305_SEALBYTES);

SALTY_FUNC(box_curve25519xchacha20poly1305_seed_keypair, 1) DO
    SALTY_INPUT_BIN(0, seed, crypto_box_curve25519xchacha20poly1305_SEEDBYTES);

    SALTY_OUTPUT_BIN(pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_CALL2(crypto_box_curve25519xchacha20poly1305_seed_keypair(
                pk.data, sk.data, seed.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(box_curve25519xchacha20poly1305_keypair, 0) DO
    SALTY_OUTPUT_BIN(pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_CALL2(crypto_box_curve25519xchacha20poly1305_keypair(
                pk.data, sk.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(box_curve25519xchacha20poly1305_easy, 4) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(3, sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xchacha20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xchacha20poly1305_easy(cipher.data,
                msg.data, msg.size, nonce.data, pk.data, sk.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xchacha20poly1305_detached, 4) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(3, sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_box_curve25519xchacha20poly1305_MACBYTES);

    SALTY_CALL2(crypto_box_curve25519xchacha20poly1305_detached(cipher.data,
                mac.data, msg.data, msg.size, nonce.data, pk.data, sk.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(box_curve25519xchacha20poly1305_open_detached, 5) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_box_curve25519xchacha20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(4, sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL_WITHERR(crypto_box_curve25519xchacha20poly1305_open_detached(
                msg.data, cipher.data, mac.data, cipher.size, nonce.data, pk.data, sk.data),
            atom_error_forged, msg);
END_OK_WITH(msg);

SALTY_FUNC(box_curve25519xchacha20poly1305_beforenm, 2) DO
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(2, sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(k, crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES);

    SALTY_CALL(crypto_box_curve25519xchacha20poly1305_beforenm(
                k.data, pk.data, sk.data), k);
END_OK_WITH(k);

SALTY_FUNC(box_curve25519xchacha20poly1305_easy_afternm, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, k, crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xchacha20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xchacha20poly1305_easy_afternm(cipher.data,
                msg.data, msg.size, nonce.data, k.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xchacha20poly1305_detached_afternm, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, k, crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_box_curve25519xchacha20poly1305_MACBYTES);

    SALTY_CALL2(crypto_box_curve25519xchacha20poly1305_detached_afternm(
                cipher.data, mac.data, msg.data, msg.size, nonce.data, k.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(box_curve25519xchacha20poly1305_open_detached_afternm, 4) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_box_curve25519xchacha20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, k, crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL_WITHERR(crypto_box_curve25519xchacha20poly1305_open_detached_afternm(
                msg.data, cipher.data, mac.data, cipher.size, nonce.data, k.data),
            atom_error_forged, msg);
END_OK_WITH(msg);

SALTY_FUNC(box_curve25519xchacha20poly1305_seal, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xchacha20poly1305_SEALBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xchacha20poly1305_seal(
                cipher.data, msg.data, msg.size, pk.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xchacha20poly1305_seal_open, 3) DO
    SALTY_INPUT_BIN(0, cipher, crypto_box_curve25519xchacha20poly1305_SEALBYTES);
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(2, sk, crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size - crypto_box_curve25519xchacha20poly1305_SEALBYTES);

    SALTY_CALL_WITHERR(crypto_box_curve25519xchacha20poly1305_seal_open(
                msg.data, cipher.data, cipher.size, pk.data, sk.data),
            atom_error_forged, msg);
END_OK_WITH(cipher);

/**
 * BOX curve25519xsalsa20poly1305
 */
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_SEEDBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_BEFORENMBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_NONCEBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_MACBYTES);
SALTY_CONST_INT64(box_curve25519xsalsa20poly1305_SEALBYTES);

SALTY_FUNC(box_curve25519xsalsa20poly1305_seed_keypair, 1) DO
    SALTY_INPUT_BIN(0, seed, crypto_box_curve25519xsalsa20poly1305_SEEDBYTES);

    SALTY_OUTPUT_BIN(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_CALL2(crypto_box_curve25519xsalsa20poly1305_seed_keypair(
                pk.data, sk.data, seed.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(box_curve25519xsalsa20poly1305_keypair, 0) DO
    SALTY_OUTPUT_BIN(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_CALL2(crypto_box_curve25519xsalsa20poly1305_keypair(
                pk.data, sk.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(box_curve25519xsalsa20poly1305_easy, 4) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(3, sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xsalsa20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xsalsa20poly1305_easy(cipher.data,
                msg.data, msg.size, nonce.data, pk.data, sk.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xsalsa20poly1305_detached, 4) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(3, sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_box_curve25519xsalsa20poly1305_MACBYTES);

    SALTY_CALL2(crypto_box_curve25519xsalsa20poly1305_detached(cipher.data,
                mac.data, msg.data, msg.size, nonce.data, pk.data, sk.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(box_curve25519xsalsa20poly1305_open_detached, 5) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_box_curve25519xsalsa20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(4, sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL_WITHERR(crypto_box_curve25519xsalsa20poly1305_open_detached(
                msg.data, cipher.data, mac.data, cipher.size, nonce.data, pk.data, sk.data),
            atom_error_forged, msg);
END_OK_WITH(msg);

SALTY_FUNC(box_curve25519xsalsa20poly1305_beforenm, 2) DO
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(2, sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(k, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);

    SALTY_CALL(crypto_box_curve25519xsalsa20poly1305_beforenm(
                k.data, pk.data, sk.data), k);
END_OK_WITH(k);

SALTY_FUNC(box_curve25519xsalsa20poly1305_easy_afternm, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, k, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xsalsa20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xsalsa20poly1305_easy_afternm(cipher.data,
                msg.data, msg.size, nonce.data, k.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xsalsa20poly1305_detached_afternm, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, k, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_box_curve25519xsalsa20poly1305_MACBYTES);

    SALTY_CALL2(crypto_box_curve25519xsalsa20poly1305_detached_afternm(
                cipher.data, mac.data, msg.data, msg.size, nonce.data, k.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(box_curve25519xsalsa20poly1305_open_detached_afternm, 4) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_box_curve25519xsalsa20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, k, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL_WITHERR(crypto_box_curve25519xsalsa20poly1305_open_detached_afternm(
                msg.data, cipher.data, mac.data, cipher.size, nonce.data, k.data),
            atom_error_forged, msg);
END_OK_WITH(msg);

SALTY_FUNC(box_curve25519xsalsa20poly1305_seal, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_box_curve25519xsalsa20poly1305_SEALBYTES + msg.size);

    SALTY_CALL(crypto_box_curve25519xsalsa20poly1305_seal(
                cipher.data, msg.data, msg.size, pk.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(box_curve25519xsalsa20poly1305_seal_open, 3) DO
    SALTY_INPUT_BIN(0, cipher, crypto_box_curve25519xsalsa20poly1305_SEALBYTES);
    SALTY_INPUT_BIN(1, pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(2, sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size - crypto_box_curve25519xsalsa20poly1305_SEALBYTES);

    SALTY_CALL_WITHERR(crypto_box_curve25519xsalsa20poly1305_seal_open(
                msg.data, cipher.data, cipher.size, pk.data, sk.data),
            atom_error_forged, msg);
END_OK_WITH(cipher);

/**
 * CORE hchacha20
 */
SALTY_FUNC(core_hchacha20, 3) DO
    SALTY_INPUT_BIN(0, in, crypto_core_hchacha20_INPUTBYTES);
    SALTY_INPUT_BIN(1, key, crypto_core_hchacha20_KEYBYTES);
    SALTY_INPUT_BIN(2, con, crypto_core_hchacha20_CONSTBYTES);

    SALTY_OUTPUT_BIN(out, crypto_core_hchacha20_OUTPUTBYTES);

    SALTY_CALL(crypto_core_hchacha20(out.data, in.data, key.data, con.data), out);
END_OK_WITH(out);
/**
 * CORE hsalsa20
 */
SALTY_FUNC(core_hsalsa20, 3) DO
    SALTY_INPUT_BIN(0, in, crypto_core_hsalsa20_INPUTBYTES);
    SALTY_INPUT_BIN(1, key, crypto_core_hsalsa20_KEYBYTES);
    SALTY_INPUT_BIN(2, con, crypto_core_hsalsa20_CONSTBYTES);

    SALTY_OUTPUT_BIN(out, crypto_core_hsalsa20_OUTPUTBYTES);

    SALTY_CALL(crypto_core_hsalsa20(out.data, in.data, key.data, con.data), out);
END_OK_WITH(out);

/**
 * GENERICHASH Blake2b
 */
SALTY_CONST_INT64(generichash_blake2b_BYTES_MIN);
SALTY_CONST_INT64(generichash_blake2b_BYTES_MAX);
SALTY_CONST_INT64(generichash_blake2b_BYTES);
SALTY_CONST_INT64(generichash_blake2b_KEYBYTES_MIN);
SALTY_CONST_INT64(generichash_blake2b_KEYBYTES_MAX);
SALTY_CONST_INT64(generichash_blake2b_KEYBYTES);
SALTY_CONST_INT64(generichash_blake2b_SALTBYTES);
SALTY_CONST_INT64(generichash_blake2b_PERSONALBYTES);

SALTY_FUNC(generichash_blake2b, 3) DO
    SALTY_INPUT_UINT64(0, outlen);
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_generichash_blake2b_KEYBYTES_MIN);

    SALTY_OUTPUT_BIN(hash, outlen);

    SALTY_CALL(crypto_generichash_blake2b(hash.data, outlen, input.data,
                input.size, key.data, key.size), hash);
END_OK_WITH(hash);

SALTY_FUNC(generichash_blake2b_salt_personal, 5) DO
    SALTY_INPUT_UINT64(0, outlen);
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_generichash_blake2b_KEYBYTES_MIN);
    SALTY_INPUT_BIN(3, salt, crypto_generichash_blake2b_SALTBYTES);
    SALTY_INPUT_BIN(4, personal, crypto_generichash_blake2b_PERSONALBYTES);

    SALTY_OUTPUT_BIN(hash, outlen);

    SALTY_CALL(crypto_generichash_blake2b_salt_personal(
                hash.data, outlen, input.data, input.size,
                key.data, key.size, salt.data, personal.data),
            hash);
END_OK_WITH(hash);

SALTY_FUNC(generichash_blake2b_init, 2) DO
    SALTY_INPUT_BIN(0, key, crypto_generichash_blake2b_KEYBYTES_MIN);
    SALTY_INPUT_UINT64(1, outlen);

    SALTY_OUTPUT_BIN(state, crypto_generichash_blake2b_statebytes());

    SALTY_CALL(crypto_generichash_blake2b_init(
                (crypto_generichash_blake2b_state *) state.data,
                key.data, key.size, outlen), state);
END_OK_WITH(state);

SALTY_FUNC(generichash_blake2b_init_salt_personal, 4) DO
    SALTY_INPUT_BIN(0, key, crypto_generichash_blake2b_KEYBYTES_MIN);
    SALTY_INPUT_UINT64(1, outlen);
    SALTY_INPUT_BIN(2, salt, crypto_generichash_blake2b_SALTBYTES);
    SALTY_INPUT_BIN(3, personal, crypto_generichash_blake2b_PERSONALBYTES);

    SALTY_OUTPUT_BIN(state, crypto_generichash_blake2b_statebytes());

    SALTY_CALL(crypto_generichash_blake2b_init_salt_personal(
                (crypto_generichash_blake2b_state *) state.data,
                key.data, key.size, outlen, salt.data, personal.data), state);
END_OK_WITH(state);

SALTY_FUNC(generichash_blake2b_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_generichash_blake2b_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_generichash_blake2b_update(
                (crypto_generichash_blake2b_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(generichash_blake2b_final, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_generichash_blake2b_statebytes());
    SALTY_INPUT_UINT64(1, outlen)

    SALTY_OUTPUT_BIN(hash, outlen);

    SALTY_CALL(crypto_generichash_blake2b_final(
                (crypto_generichash_blake2b_state *) state.data,
                hash.data, outlen), hash);
END_OK_WITH(hash);

/**
 * HASH Sha256
 */
SALTY_CONST_INT64(hash_sha256_BYTES);

SALTY_FUNC(hash_sha256, 1) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);

    SALTY_OUTPUT_BIN(hash, crypto_hash_sha256_BYTES);

    SALTY_CALL(crypto_hash_sha256(hash.data, msg.data, msg.size), hash);
END_OK_WITH(hash);

SALTY_FUNC(hash_sha256_verify, 2) DO
    SALTY_INPUT_BIN(0, hash, crypto_hash_sha256_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);

    SALTY_CALL_SIMPLE_WITHERR(crypto_hash_sha256_verify(
                hash.data, msg.data, msg.size),
            atom_error_no_match);
END_OK;

SALTY_FUNC(hash_sha256_init, 0) DO
    SALTY_OUTPUT_BIN(state, crypto_hash_sha256_statebytes());

    SALTY_CALL(crypto_hash_sha256_init(
                (crypto_hash_sha256_state *) state.data), state);
END_OK_WITH(state);

SALTY_FUNC(hash_sha256_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha256_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_hash_sha256_update(
                (crypto_hash_sha256_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(hash_sha256_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha256_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_hash_sha256_BYTES);

    SALTY_CALL(crypto_hash_sha256_final(
                (crypto_hash_sha256_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(hash_sha256_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha256_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_hash_sha256_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_hash_sha256_final_verify(
                (crypto_hash_sha256_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * HASH Sha512
 */
SALTY_CONST_INT64(hash_sha512_BYTES);

SALTY_FUNC(hash_sha512, 1) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);

    SALTY_OUTPUT_BIN(hash, crypto_hash_sha512_BYTES);

    SALTY_CALL(crypto_hash_sha512(hash.data, msg.data, msg.size), hash);
END_OK_WITH(hash);

SALTY_FUNC(hash_sha512_verify, 2) DO
    SALTY_INPUT_BIN(0, hash, crypto_hash_sha512_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);

    SALTY_CALL_SIMPLE_WITHERR(crypto_hash_sha512_verify(
                hash.data, msg.data, msg.size),
            atom_error_no_match);
END_OK;

SALTY_FUNC(hash_sha512_init, 0) DO
    SALTY_OUTPUT_BIN(state, crypto_hash_sha512_statebytes());

    SALTY_CALL(crypto_hash_sha512_init(
                (crypto_hash_sha512_state *) state.data), state);
END_OK_WITH(state);

SALTY_FUNC(hash_sha512_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha512_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_hash_sha512_update(
                (crypto_hash_sha512_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(hash_sha512_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha512_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_hash_sha512_BYTES);

    SALTY_CALL(crypto_hash_sha512_final(
                (crypto_hash_sha512_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(hash_sha512_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_hash_sha512_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_hash_sha512_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_hash_sha512_final_verify(
                (crypto_hash_sha512_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * KDF Blake2b
 */
SALTY_CONST_INT64(kdf_blake2b_BYTES_MIN);
SALTY_CONST_INT64(kdf_blake2b_BYTES_MAX);
SALTY_CONST_INT64(kdf_blake2b_CONTEXTBYTES);
SALTY_CONST_INT64(kdf_blake2b_KEYBYTES);

SALTY_FUNC(kdf_blake2b_derive_from_key, 4) DO
    SALTY_INPUT_UINT64(0, subkey_len);
    SALTY_INPUT_UINT64(1, subkey_id);
    SALTY_INPUT_BIN(2, ctx, crypto_kdf_blake2b_CONTEXTBYTES);
    SALTY_INPUT_BIN(3, key, crypto_kdf_blake2b_KEYBYTES);

    SALTY_OUTPUT_BIN(subkey, subkey_len);

    SALTY_CALL(crypto_kdf_blake2b_derive_from_key(
                subkey.data, subkey_len, subkey_id,
                (const char *) ctx.data, key.data), subkey);
END_OK_WITH(subkey);

/**
 * KX X25519Blake2b
 */
SALTY_CONST_INT64(kx_PUBLICKEYBYTES);
SALTY_CONST_INT64(kx_SECRETKEYBYTES);
SALTY_CONST_INT64(kx_SEEDBYTES);
SALTY_CONST_INT64(kx_SESSIONKEYBYTES);

SALTY_FUNC(kx_seed_keypair, 1) DO
    SALTY_INPUT_BIN(0, seed, crypto_kx_SEEDBYTES);

    SALTY_OUTPUT_BIN(pk, crypto_kx_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_kx_SECRETKEYBYTES);

    SALTY_CALL2(crypto_kx_seed_keypair(pk.data, sk.data, seed.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(kx_keypair, 0) DO
    SALTY_OUTPUT_BIN(pk, crypto_kx_PUBLICKEYBYTES);
    SALTY_OUTPUT_BIN(sk, crypto_kx_SECRETKEYBYTES);

    SALTY_CALL2(crypto_kx_keypair(pk.data, sk.data), pk, sk);
END_OK_WITH2(pk, sk);

SALTY_FUNC(kx_client_session_keys, 3) DO
    SALTY_INPUT_BIN(0, client_pk, crypto_kx_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(1, client_sk, crypto_kx_SECRETKEYBYTES);
    SALTY_INPUT_BIN(2, server_pk, crypto_kx_PUBLICKEYBYTES);

    SALTY_OUTPUT_BIN(rx, crypto_kx_SESSIONKEYBYTES);
    SALTY_OUTPUT_BIN(tx, crypto_kx_SESSIONKEYBYTES);

    SALTY_CALL2(crypto_kx_client_session_keys(rx.data, tx.data,
                client_pk.data, client_sk.data, server_pk.data), rx, tx);
END_OK_WITH2(rx, tx);

SALTY_FUNC(kx_server_session_keys, 3) DO
    SALTY_INPUT_BIN(0, server_pk, crypto_kx_PUBLICKEYBYTES);
    SALTY_INPUT_BIN(1, server_sk, crypto_kx_SECRETKEYBYTES);
    SALTY_INPUT_BIN(2, client_pk, crypto_kx_PUBLICKEYBYTES);

    SALTY_OUTPUT_BIN(rx, crypto_kx_SESSIONKEYBYTES);
    SALTY_OUTPUT_BIN(tx, crypto_kx_SESSIONKEYBYTES);

    SALTY_CALL2(crypto_kx_server_session_keys(rx.data, tx.data,
                server_pk.data, server_sk.data, client_pk.data), rx, tx);
END_OK_WITH2(rx, tx);

/**
 * ONETIMEAUTH Poly1305
 */
SALTY_CONST_INT64(onetimeauth_poly1305_BYTES);
SALTY_CONST_INT64(onetimeauth_poly1305_KEYBYTES);

SALTY_FUNC(onetimeauth_poly1305, 2) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_onetimeauth_poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(mac, crypto_onetimeauth_poly1305_BYTES);

    SALTY_CALL(crypto_onetimeauth_poly1305(mac.data, msg.data, msg.size, key.data), mac);
END_OK_WITH(mac);

SALTY_FUNC(onetimeauth_poly1305_verify, 3) DO
    SALTY_INPUT_BIN(0, mac, crypto_onetimeauth_poly1305_BYTES);
    SALTY_INPUT_BIN(1, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, key, crypto_onetimeauth_poly1305_KEYBYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_onetimeauth_poly1305_verify(
                mac.data, msg.data, msg.size, key.data),
            atom_error_no_match);
END_OK;

SALTY_FUNC(onetimeauth_poly1305_init, 1) DO
    SALTY_INPUT_BIN(0, key, crypto_onetimeauth_poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(state, crypto_onetimeauth_poly1305_statebytes());

    SALTY_CALL(crypto_onetimeauth_poly1305_init(
                (crypto_onetimeauth_poly1305_state *) state.data,
                key.data), state);
END_OK_WITH(state);

SALTY_FUNC(onetimeauth_poly1305_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_onetimeauth_poly1305_statebytes());
    SALTY_INPUT_BIN(1, input, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_onetimeauth_poly1305_update(
                (crypto_onetimeauth_poly1305_state *) state.data,
                input.data, input.size), state);
END_OK_WITH(state);

SALTY_FUNC(onetimeauth_poly1305_final, 1) DO
    SALTY_INPUT_BIN(0, state, crypto_onetimeauth_poly1305_statebytes());

    SALTY_OUTPUT_BIN(hash, crypto_onetimeauth_poly1305_BYTES);

    SALTY_CALL(crypto_onetimeauth_poly1305_final(
                (crypto_onetimeauth_poly1305_state *) state.data,
                hash.data), hash);
END_OK_WITH(hash);

SALTY_FUNC(onetimeauth_poly1305_final_verify, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_onetimeauth_poly1305_statebytes());
    SALTY_INPUT_BIN(1, expect, crypto_onetimeauth_poly1305_BYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_onetimeauth_poly1305_final_verify(
                (crypto_onetimeauth_poly1305_state *) state.data, expect.data),
            atom_error_forged);
END_OK;

/**
 * SCALARMULT Curve25519
 */
SALTY_CONST_INT64(scalarmult_curve25519_BYTES);
SALTY_CONST_INT64(scalarmult_curve25519_SCALARBYTES);

SALTY_FUNC(scalarmult_curve25519_base, 1) DO
    SALTY_INPUT_BIN(0, n, crypto_scalarmult_curve25519_SCALARBYTES);

    SALTY_OUTPUT_BIN(q, crypto_scalarmult_curve25519_BYTES);

    SALTY_CALL(crypto_scalarmult_curve25519_base(q.data, n.data), q)
END_OK_WITH(q);

SALTY_FUNC(scalarmult_curve25519, 2) DO
    SALTY_INPUT_BIN(0, n, crypto_scalarmult_curve25519_SCALARBYTES);
    SALTY_INPUT_BIN(1, p, crypto_scalarmult_curve25519_SCALARBYTES);

    SALTY_OUTPUT_BIN(q, crypto_scalarmult_curve25519_BYTES);

    SALTY_CALL(crypto_scalarmult_curve25519(q.data, n.data, p.data), q)
END_OK_WITH(q);

/**
 * SECRETBOX XChacha20Poly1305
 */
SALTY_CONST_INT64(secretbox_xchacha20poly1305_KEYBYTES);
SALTY_CONST_INT64(secretbox_xchacha20poly1305_NONCEBYTES);
SALTY_CONST_INT64(secretbox_xchacha20poly1305_MACBYTES);

SALTY_FUNC(secretbox_xchacha20poly1305_easy, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, key, crypto_secretbox_xchacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_secretbox_xchacha20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_secretbox_xchacha20poly1305_easy(
                cipher.data, msg.data, msg.size, nonce.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(secretbox_xchacha20poly1305_detached, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, key, crypto_secretbox_xchacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_secretbox_xchacha20poly1305_MACBYTES);

    SALTY_CALL2(crypto_secretbox_xchacha20poly1305_detached(
                cipher.data, mac.data, msg.data, msg.size, nonce.data, key.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(secretbox_xchacha20poly1305_open_detached, 4) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_secretbox_xchacha20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, key, crypto_secretbox_xchacha20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL(crypto_secretbox_xchacha20poly1305_open_detached(msg.data,
                cipher.data, mac.data, cipher.size, nonce.data, key.data), msg);
END_OK_WITH(msg);

/**
 * SECRETBOX XSalsa20Poly1305
 */
SALTY_CONST_INT64(secretbox_xsalsa20poly1305_KEYBYTES);
SALTY_CONST_INT64(secretbox_xsalsa20poly1305_NONCEBYTES);
SALTY_CONST_INT64(secretbox_xsalsa20poly1305_MACBYTES);

SALTY_FUNC(secretbox_xsalsa20poly1305_easy, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, key, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, crypto_secretbox_xsalsa20poly1305_MACBYTES + msg.size);

    SALTY_CALL(crypto_secretbox_xsalsa20poly1305_easy(
                cipher.data, msg.data, msg.size, nonce.data, key.data), cipher);
END_OK_WITH(cipher);

SALTY_FUNC(secretbox_xsalsa20poly1305_detached, 3) DO
    SALTY_INPUT_BIN(0, msg, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, nonce, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(2, key, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(cipher, msg.size);
    SALTY_OUTPUT_BIN(mac, crypto_secretbox_xsalsa20poly1305_MACBYTES);

    SALTY_CALL2(crypto_secretbox_xsalsa20poly1305_detached(
                cipher.data, mac.data, msg.data, msg.size, nonce.data, key.data),
            cipher, mac);
END_OK_WITH2(cipher, mac);

SALTY_FUNC(secretbox_xsalsa20poly1305_open_detached, 4) DO
    SALTY_INPUT_BIN(0, cipher, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, mac, crypto_secretbox_xsalsa20poly1305_MACBYTES);
    SALTY_INPUT_BIN(2, nonce, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    SALTY_INPUT_BIN(3, key, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

    SALTY_OUTPUT_BIN(msg, cipher.size);

    SALTY_CALL(crypto_secretbox_xsalsa20poly1305_open_detached(msg.data,
                cipher.data, mac.data, cipher.size, nonce.data, key.data), msg);
END_OK_WITH(msg);

/**
 * SHORTHASH Siphash24
 */
SALTY_CONST_INT64(shorthash_siphash24_BYTES);
SALTY_CONST_INT64(shorthash_siphash24_KEYBYTES);

SALTY_FUNC(shorthash_siphash24, 2) DO
    SALTY_INPUT_BIN(0, data, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_shorthash_siphash24_KEYBYTES);

    SALTY_OUTPUT_BIN(hash, crypto_shorthash_siphash24_BYTES);

    SALTY_CALL(crypto_shorthash_siphash24(
                hash.data, data.data, data.size, key.data), hash);
END_OK_WITH(hash);

/**
 * SHORTHASH Siphashx24
 */
SALTY_CONST_INT64(shorthash_siphashx24_BYTES);
SALTY_CONST_INT64(shorthash_siphashx24_KEYBYTES);

SALTY_FUNC(shorthash_siphashx24, 2) DO
    SALTY_INPUT_BIN(0, data, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, key, crypto_shorthash_siphashx24_KEYBYTES);

    SALTY_OUTPUT_BIN(hash, crypto_shorthash_siphashx24_BYTES);

    SALTY_CALL(crypto_shorthash_siphashx24(
                hash.data, data.data, data.size, key.data), hash);
END_OK_WITH(hash);

/**
 * SIGN Ed25519
 */
SALTY_CONST_INT64(sign_ed25519_BYTES);
SALTY_CONST_INT64(sign_ed25519_SEEDBYTES);
SALTY_CONST_INT64(sign_ed25519_PUBLICKEYBYTES);
SALTY_CONST_INT64(sign_ed25519_SECRETKEYBYTES);

SALTY_FUNC(sign_ed25519_seed_keypair, 1) DO
    unsigned char tmp[crypto_sign_ed25519_PUBLICKEYBYTES];

    SALTY_INPUT_BIN(0, seed, crypto_sign_ed25519_SEEDBYTES);

    SALTY_OUTPUT_BIN(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    SALTY_CALL(crypto_sign_ed25519_seed_keypair(
                tmp, sk.data, seed.data), sk);
END_OK_WITH(sk);

SALTY_FUNC(sign_ed25519_keypair, 0) DO
    unsigned char tmp[crypto_sign_ed25519_PUBLICKEYBYTES];

    SALTY_OUTPUT_BIN(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    SALTY_CALL(crypto_sign_ed25519_keypair(
                tmp, sk.data), sk);
END_OK_WITH(sk);

SALTY_FUNC(sign_ed25519, 2) DO
    SALTY_INPUT_BIN(0, data, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, sk, crypto_sign_ed25519_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(sm, data.size + crypto_sign_ed25519_BYTES);

    SALTY_CALL(crypto_sign_ed25519(
                sm.data, NULL, data.data, data.size, sk.data), sm);
END_OK_WITH(sm);

SALTY_FUNC(sign_ed25519_detached, 2) DO
    SALTY_INPUT_BIN(0, data, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(1, sk, crypto_sign_ed25519_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(sig, crypto_sign_ed25519_BYTES);

    SALTY_CALL(crypto_sign_ed25519_detached(
                sig.data, NULL, data.data, data.size, sk.data), sig);
END_OK_WITH(sig);

SALTY_FUNC(sign_ed25519_verify_detached, 3) DO
    SALTY_INPUT_BIN(0, sig, crypto_sign_ed25519_BYTES);
    SALTY_INPUT_BIN(1, data, SALTY_BIN_NO_SIZE);
    SALTY_INPUT_BIN(2, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

    SALTY_CALL_SIMPLE_WITHERR(crypto_sign_ed25519_verify_detached(
                sig.data, data.data, data.size, pk.data),
            atom_error_forged);
END_OK;

SALTY_FUNC(sign_ed25519ph_init, 0) DO
    SALTY_OUTPUT_BIN(state, crypto_sign_ed25519ph_statebytes());

    SALTY_CALL(crypto_sign_ed25519ph_init(
                (crypto_sign_ed25519ph_state *) state.data), state);
END_OK_WITH(state);

SALTY_FUNC(sign_ed25519ph_update, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_sign_ed25519ph_statebytes());
    SALTY_INPUT_BIN(1, data, SALTY_BIN_NO_SIZE);

    SALTY_CALL(crypto_sign_ed25519ph_update(
                (crypto_sign_ed25519ph_state *) state.data,
                data.data, data.size), state);
END_OK_WITH(state);

SALTY_FUNC(sign_ed25519ph_final_create, 2) DO
    SALTY_INPUT_BIN(0, state, crypto_sign_ed25519ph_statebytes());
    SALTY_INPUT_BIN(1, sk, crypto_sign_ed25519_SECRETKEYBYTES);

    SALTY_OUTPUT_BIN(sig, crypto_sign_ed25519_BYTES);

    SALTY_CALL(crypto_sign_ed25519ph_final_create(
                (crypto_sign_ed25519ph_state *) state.data,
                sig.data, NULL, sk.data), sig);
END_OK_WITH(sig);

SALTY_FUNC(sign_ed25519ph_final_verify, 3) DO
    SALTY_INPUT_BIN(0, state, crypto_sign_ed25519ph_statebytes());
    SALTY_INPUT_BIN(1, sig, crypto_sign_ed25519_BYTES);
    SALTY_INPUT_BIN(2, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

    SALTY_CALL_SIMPLE(crypto_sign_ed25519ph_final_verify(
                (crypto_sign_ed25519ph_state *) state.data,
                sig.data, pk.data));
END_OK;

/**
 * RANDOMBYTES
 */
SALTY_CONST_INT64(randombytes_SEEDBYTES);

SALTY_FUNC(randombytes_random, 0) DO
    return enif_make_uint64(env, randombytes_random());
END;

SALTY_FUNC(randombytes_stir, 0) DO
    randombytes_stir();
END_OK;

SALTY_FUNC(randombytes_uniform, 1) DO
    SALTY_INPUT_UINT64(0, upper);
    return enif_make_ulong(env, randombytes_uniform((uint32_t) (upper & 0xffffffff)));
END;

SALTY_FUNC(randombytes_buf, 1) DO
    SALTY_INPUT_UINT64(0, len);

    SALTY_OUTPUT_BIN(buff, len);

    randombytes_buf(buff.data, len);
END_OK_WITH(buff);

SALTY_FUNC(randombytes_buf_deterministic, 2) DO
    SALTY_INPUT_UINT64(0, outlen);
    SALTY_INPUT_BIN(1, seed, crypto_randombytes_SEEDBYTES);

    SALTY_OUTPUT_BIN(buff, outlen);

    randombytes_buf_deterministic(buff.data, outlen, seed.data);
END_OK_WITH(buff);

SALTY_FUNC(randombytes_close, 0) DO
    SALTY_CALL_SIMPLE(randombytes_close());
END_OK;

/***********************************************
 * export
 ***********************************************/

static ErlNifFunc
salty_exports[] = {
    SALTY_EXPORT_FUNC(init, 0),
    SALTY_EXPORT_FUNC(memcmp, 2),

    SALTY_EXPORT_CONS(aead_aes256gcm_KEYBYTES, 0),
    SALTY_EXPORT_CONS(aead_aes256gcm_NSECBYTES, 0),
    SALTY_EXPORT_CONS(aead_aes256gcm_NPUBBYTES, 0),
    SALTY_EXPORT_CONS(aead_aes256gcm_ABYTES, 0),
    SALTY_EXPORT_FUNC(aead_aes256gcm_is_available, 0),
    SALTY_EXPORT_FUNC(aead_aes256gcm_encrypt, 5),
    SALTY_EXPORT_FUNC(aead_aes256gcm_encrypt_detached, 5),
    SALTY_EXPORT_FUNC(aead_aes256gcm_decrypt_detached, 6),

    SALTY_EXPORT_CONS(aead_chacha20poly1305_KEYBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_NSECBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_NPUBBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_ABYTES, 0),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_encrypt, 5),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_encrypt_detached, 5),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_decrypt_detached, 6),
    
    SALTY_EXPORT_CONS(aead_chacha20poly1305_ietf_KEYBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_ietf_NSECBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_ietf_NPUBBYTES, 0),
    SALTY_EXPORT_CONS(aead_chacha20poly1305_ietf_ABYTES, 0),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_ietf_encrypt, 5),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_ietf_encrypt_detached, 5),
    SALTY_EXPORT_FUNC(aead_chacha20poly1305_ietf_decrypt_detached, 6),

    SALTY_EXPORT_CONS(aead_xchacha20poly1305_ietf_KEYBYTES, 0),
    SALTY_EXPORT_CONS(aead_xchacha20poly1305_ietf_NSECBYTES, 0),
    SALTY_EXPORT_CONS(aead_xchacha20poly1305_ietf_NPUBBYTES, 0),
    SALTY_EXPORT_CONS(aead_xchacha20poly1305_ietf_ABYTES, 0),
    SALTY_EXPORT_FUNC(aead_xchacha20poly1305_ietf_encrypt, 5),
    SALTY_EXPORT_FUNC(aead_xchacha20poly1305_ietf_encrypt_detached, 5),
    SALTY_EXPORT_FUNC(aead_xchacha20poly1305_ietf_decrypt_detached, 6),

    SALTY_EXPORT_CONS(auth_hmacsha256_BYTES, 0),
    SALTY_EXPORT_CONS(auth_hmacsha256_KEYBYTES, 0),
    SALTY_EXPORT_FUNC(auth_hmacsha256, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha256_verify, 3),
    SALTY_EXPORT_FUNC(auth_hmacsha256_init, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha256_update, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha256_final, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha256_final_verify, 2),

    SALTY_EXPORT_CONS(auth_hmacsha512_BYTES, 0),
    SALTY_EXPORT_CONS(auth_hmacsha512_KEYBYTES, 0),
    SALTY_EXPORT_FUNC(auth_hmacsha512, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha512_verify, 3),
    SALTY_EXPORT_FUNC(auth_hmacsha512_init, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha512_update, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha512_final, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha512_final_verify, 2),

    SALTY_EXPORT_CONS(auth_hmacsha512256_BYTES, 0),
    SALTY_EXPORT_CONS(auth_hmacsha512256_KEYBYTES, 0),
    SALTY_EXPORT_FUNC(auth_hmacsha512256, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha512256_verify, 3),
    SALTY_EXPORT_FUNC(auth_hmacsha512256_init, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha512256_update, 2),
    SALTY_EXPORT_FUNC(auth_hmacsha512256_final, 1),
    SALTY_EXPORT_FUNC(auth_hmacsha512256_final_verify, 2),

    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_SEEDBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_PUBLICKEYBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_SECRETKEYBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_BEFORENMBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_NONCEBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_MACBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xchacha20poly1305_SEALBYTES, 0),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_seed_keypair, 1),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_keypair, 0),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_easy, 4),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_detached, 4),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_open_detached, 5),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_beforenm, 2),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_easy_afternm, 3),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_detached_afternm, 3),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_open_detached_afternm, 4),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_seal, 2),
    SALTY_EXPORT_FUNC(box_curve25519xchacha20poly1305_seal_open, 3),

    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_SEEDBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_PUBLICKEYBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_SECRETKEYBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_BEFORENMBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_NONCEBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_MACBYTES, 0),
    SALTY_EXPORT_CONS(box_curve25519xsalsa20poly1305_SEALBYTES, 0),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_seed_keypair, 1),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_keypair, 0),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_easy, 4),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_detached, 4),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_open_detached, 5),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_beforenm, 2),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_easy_afternm, 3),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_detached_afternm, 3),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_open_detached_afternm, 4),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_seal, 2),
    SALTY_EXPORT_FUNC(box_curve25519xsalsa20poly1305_seal_open, 3),

    SALTY_EXPORT_FUNC(core_hchacha20, 3),
    SALTY_EXPORT_FUNC(core_hsalsa20, 3),

    SALTY_EXPORT_CONS(generichash_blake2b_BYTES_MIN, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_BYTES_MAX, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_BYTES, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_KEYBYTES_MIN, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_KEYBYTES_MAX, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_KEYBYTES, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_SALTBYTES, 0),
    SALTY_EXPORT_CONS(generichash_blake2b_PERSONALBYTES, 0),
    SALTY_EXPORT_FUNC(generichash_blake2b, 3),
    SALTY_EXPORT_FUNC(generichash_blake2b_salt_personal, 5),
    SALTY_EXPORT_FUNC(generichash_blake2b_init, 2),
    SALTY_EXPORT_FUNC(generichash_blake2b_init_salt_personal, 4),
    SALTY_EXPORT_FUNC(generichash_blake2b_update, 2),
    SALTY_EXPORT_FUNC(generichash_blake2b_final, 2),

    SALTY_EXPORT_CONS(hash_sha256_BYTES, 0),
    SALTY_EXPORT_FUNC(hash_sha256, 1),
    SALTY_EXPORT_FUNC(hash_sha256_verify, 2),
    SALTY_EXPORT_FUNC(hash_sha256_init, 0),
    SALTY_EXPORT_FUNC(hash_sha256_update, 2),
    SALTY_EXPORT_FUNC(hash_sha256_final, 1),
    SALTY_EXPORT_FUNC(hash_sha256_final_verify, 2),

    SALTY_EXPORT_CONS(hash_sha512_BYTES, 0),
    SALTY_EXPORT_FUNC(hash_sha512, 1),
    SALTY_EXPORT_FUNC(hash_sha512_verify, 2),
    SALTY_EXPORT_FUNC(hash_sha512_init, 0),
    SALTY_EXPORT_FUNC(hash_sha512_update, 2),
    SALTY_EXPORT_FUNC(hash_sha512_final, 1),
    SALTY_EXPORT_FUNC(hash_sha512_final_verify, 2),

    SALTY_EXPORT_CONS(kdf_blake2b_BYTES_MIN, 0),
    SALTY_EXPORT_CONS(kdf_blake2b_BYTES_MAX, 0),
    SALTY_EXPORT_CONS(kdf_blake2b_CONTEXTBYTES, 0),
    SALTY_EXPORT_CONS(kdf_blake2b_KEYBYTES, 0),
    SALTY_EXPORT_FUNC(kdf_blake2b_derive_from_key, 4),

    SALTY_EXPORT_CONS(kx_PUBLICKEYBYTES, 0),
    SALTY_EXPORT_CONS(kx_SECRETKEYBYTES, 0),
    SALTY_EXPORT_CONS(kx_SEEDBYTES, 0),
    SALTY_EXPORT_CONS(kx_SESSIONKEYBYTES, 0),
    SALTY_EXPORT_FUNC(kx_seed_keypair, 1),
    SALTY_EXPORT_FUNC(kx_keypair, 0),
    SALTY_EXPORT_FUNC(kx_client_session_keys, 3),
    SALTY_EXPORT_FUNC(kx_server_session_keys, 3),

    SALTY_EXPORT_CONS(onetimeauth_poly1305_BYTES, 0),
    SALTY_EXPORT_CONS(onetimeauth_poly1305_KEYBYTES, 0),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305, 2),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305_verify, 3),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305_init, 1),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305_update, 2),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305_final, 1),
    SALTY_EXPORT_FUNC(onetimeauth_poly1305_final_verify, 2),

    SALTY_EXPORT_CONS(scalarmult_curve25519_BYTES, 0),
    SALTY_EXPORT_CONS(scalarmult_curve25519_SCALARBYTES, 0),
    SALTY_EXPORT_FUNC(scalarmult_curve25519_base, 1),
    SALTY_EXPORT_FUNC(scalarmult_curve25519, 2),

    SALTY_EXPORT_CONS(secretbox_xchacha20poly1305_KEYBYTES, 0),
    SALTY_EXPORT_CONS(secretbox_xchacha20poly1305_NONCEBYTES, 0),
    SALTY_EXPORT_CONS(secretbox_xchacha20poly1305_MACBYTES, 0),
    SALTY_EXPORT_FUNC(secretbox_xchacha20poly1305_easy, 3),
    SALTY_EXPORT_FUNC(secretbox_xchacha20poly1305_detached, 3),
    SALTY_EXPORT_FUNC(secretbox_xchacha20poly1305_open_detached, 4),

    SALTY_EXPORT_CONS(secretbox_xsalsa20poly1305_KEYBYTES, 0),
    SALTY_EXPORT_CONS(secretbox_xsalsa20poly1305_NONCEBYTES, 0),
    SALTY_EXPORT_CONS(secretbox_xsalsa20poly1305_MACBYTES, 0),
    SALTY_EXPORT_FUNC(secretbox_xsalsa20poly1305_easy, 3),
    SALTY_EXPORT_FUNC(secretbox_xsalsa20poly1305_detached, 3),
    SALTY_EXPORT_FUNC(secretbox_xsalsa20poly1305_open_detached, 4),

    SALTY_EXPORT_CONS(shorthash_siphash24_BYTES, 0),
    SALTY_EXPORT_CONS(shorthash_siphash24_KEYBYTES, 0),
    SALTY_EXPORT_CONS(shorthash_siphash24, 2),

    SALTY_EXPORT_CONS(shorthash_siphashx24_BYTES, 0),
    SALTY_EXPORT_CONS(shorthash_siphashx24_KEYBYTES, 0),
    SALTY_EXPORT_CONS(shorthash_siphashx24, 2),

    SALTY_EXPORT_CONS(sign_ed25519_BYTES, 0),
    SALTY_EXPORT_CONS(sign_ed25519_SEEDBYTES, 0),
    SALTY_EXPORT_CONS(sign_ed25519_PUBLICKEYBYTES, 0),
    SALTY_EXPORT_CONS(sign_ed25519_SECRETKEYBYTES, 0),
    SALTY_EXPORT_FUNC(sign_ed25519_seed_keypair, 1),
    SALTY_EXPORT_FUNC(sign_ed25519_keypair, 0),
    SALTY_EXPORT_FUNC(sign_ed25519, 2),
    SALTY_EXPORT_FUNC(sign_ed25519_detached, 2),
    SALTY_EXPORT_FUNC(sign_ed25519_verify_detached, 3),
    SALTY_EXPORT_FUNC(sign_ed25519ph_init, 0),
    SALTY_EXPORT_FUNC(sign_ed25519ph_update, 2),
    SALTY_EXPORT_FUNC(sign_ed25519ph_final_create, 2),
    SALTY_EXPORT_FUNC(sign_ed25519ph_final_verify, 3),

    SALTY_EXPORT_FUNC(randombytes_SEEDBYTES, 0),
    SALTY_EXPORT_FUNC(randombytes_random, 0),
    SALTY_EXPORT_FUNC(randombytes_stir, 0),
    SALTY_EXPORT_FUNC(randombytes_uniform, 1),
    SALTY_EXPORT_FUNC(randombytes_buf, 1),
    SALTY_EXPORT_FUNC(randombytes_buf_deterministic, 2),
    SALTY_EXPORT_FUNC(randombytes_close, 0),
};

ERL_NIF_INIT(Elixir.Salty.Nif, salty_exports, salty_onload, NULL, NULL, NULL)
