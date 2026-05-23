#pragma once
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// RAII
struct PKEYDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct CTXDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct CipherDeleter { void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); } };
struct BIODeleter { void operator()(BIO* b) const { BIO_free_all(b); } };