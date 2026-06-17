#pragma once
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <ykpiv/ykpiv.h>

// RAII
struct YKPivStateDeleter {
    void operator()(ykpiv_state* p) const {
        if (p) {
            ykpiv_disconnect(p);
            ykpiv_done(p);
        }
    }
};
using YKPIV_STATE = std::unique_ptr<ykpiv_state, YKPivStateDeleter>;

struct PKEYDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct CTXDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct CipherDeleter { void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); } };
struct BIODeleter { void operator()(BIO* b) const { BIO_free_all(b); } };