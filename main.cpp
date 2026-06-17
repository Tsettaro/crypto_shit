#include "CryptEpstein.h"

using PRIVATE_KEY = std::unique_ptr<EVP_PKEY, PKEYDeleter>;
using PUBLIC_KEY_CONTEXT = std::unique_ptr<EVP_PKEY_CTX, CTXDeleter>;

PRIVATE_KEY get_yubikey_public_key() {
    ykpiv_state* raw_state = nullptr;
    if (ykpiv_init(&raw_state, 0) != YKPIV_OK) {
        throw std::runtime_error("Failed to initialize YubiKey state.");
    }
    YKPIV_STATE state(raw_state);

    if (ykpiv_connect(state.get(), nullptr) != YKPIV_OK) {
        throw std::runtime_error("Failed to connect to YubiKey. Is it plugged in?");
    }

    uint8_t* cert_data = nullptr;
    size_t cert_len = 0;
    // PIV slot 9D is reserved for Key Management, appropriate for asymmetric encryption/decryption
    ykpiv_rc rc = ykpiv_util_read_cert(state.get(), YKPIV_KEY_KEYMGM, &cert_data, &cert_len);

    EVP_PKEY* pkey = nullptr;

    if (rc == YKPIV_OK && cert_data != nullptr && cert_len > 0) {
        std::cout << "Key certificate found on YubiKey. Parsing...\n";
        const unsigned char* p = cert_data;
        X509* x509 = d2i_X509(nullptr, &p, cert_len);
        ykpiv_util_free(state.get(), cert_data);

        if (!x509) {
            throw std::runtime_error("Failed to parse X509 certificate from YubiKey.");
        }

        pkey = X509_get_pubkey(x509);
        X509_free(x509);

        if (!pkey) {
            throw std::runtime_error("Failed to extract public key from YubiKey certificate.");
        }
    } else {
        std::cout << "Key not found on YubiKey, generating a new one...\n";
        std::cout << "Using default management key. In production, prompt for management key.\n";
        unsigned char mgmKey[24] = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
        if (ykpiv_authenticate(state.get(), mgmKey) != YKPIV_OK) {
            throw std::runtime_error("Failed to authenticate with YubiKey using default management key.");
        }

        uint8_t* modulus = nullptr;
        size_t modulus_len = 0;
        uint8_t* exp = nullptr;
        size_t exp_len = 0;
        uint8_t* point = nullptr;
        size_t point_len = 0;

        rc = ykpiv_util_generate_key(state.get(), YKPIV_KEY_KEYMGM, YKPIV_ALGO_RSA2048, YKPIV_PINPOLICY_DEFAULT, YKPIV_TOUCHPOLICY_DEFAULT, &modulus, &modulus_len, &exp, &exp_len, &point, &point_len);
        if (point) ykpiv_util_free(state.get(), point);

        if (rc != YKPIV_OK) {
            if (modulus) ykpiv_util_free(state.get(), modulus);
            if (exp) ykpiv_util_free(state.get(), exp);
            throw std::runtime_error("Failed to generate key on YubiKey.");
        }

        BIGNUM* n = BN_bin2bn(modulus, modulus_len, nullptr);
        BIGNUM* e = BN_bin2bn(exp, exp_len, nullptr);

        ykpiv_util_free(state.get(), modulus);
        ykpiv_util_free(state.get(), exp);

        if (!n || !e) {
            if (n) BN_free(n);
            if (e) BN_free(e);
            throw std::runtime_error("Failed to convert modulus/exponent to BIGNUM.");
        }

        RSA* rsa = RSA_new();
        if (!rsa || !RSA_set0_key(rsa, n, e, nullptr)) {
            RSA_free(rsa);
            BN_free(n);
            BN_free(e);
            throw std::runtime_error("Failed to create RSA object from parameters.");
        }

        pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
            if (pkey) EVP_PKEY_free(pkey);
            RSA_free(rsa);
            throw std::runtime_error("Failed to assign RSA to EVP_PKEY.");
        }

        // We also need to create a dummy cert and store it so we know the key exists later
        X509* dummy_x509 = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(dummy_x509), 1);
        X509_gmtime_adj(X509_getm_notBefore(dummy_x509), 0);
        X509_gmtime_adj(X509_getm_notAfter(dummy_x509), 31536000L * 10); // 10 years
        X509_set_pubkey(dummy_x509, pkey);
        X509_NAME* name = X509_get_subject_name(dummy_x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"YubiKey EpstProject Key", -1, -1, 0);
        X509_set_issuer_name(dummy_x509, name);

        EVP_PKEY* dummy_sign_key = EVP_PKEY_new();
        RSA* dummy_rsa = RSA_new();
        BIGNUM* dummy_e = BN_new();
        BN_set_word(dummy_e, RSA_F4);
        RSA_generate_key_ex(dummy_rsa, 2048, dummy_e, nullptr);
        BN_free(dummy_e);
        EVP_PKEY_assign_RSA(dummy_sign_key, dummy_rsa);

        X509_sign(dummy_x509, dummy_sign_key, EVP_sha256());

        unsigned char* cert_der = nullptr;
        int cert_der_len = i2d_X509(dummy_x509, &cert_der);
        if (cert_der_len > 0) {
            ykpiv_util_write_cert(state.get(), YKPIV_KEY_KEYMGM, cert_der, cert_der_len, 0); // 0 = default certinfo
            OPENSSL_free(cert_der);
        }

        EVP_PKEY_free(dummy_sign_key);
        X509_free(dummy_x509);
    }

    return PRIVATE_KEY(pkey);
}
using KEY_BIO = std::unique_ptr<BIO, BIODeleter>;
using CIPHER_CONTEXT = std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter>;

#define DATA_WRITE(data) reinterpret_cast<const char*>(data)
#define DATA_READ(data) reinterpret_cast<char*>(data)

constexpr size_t BUFFER_SIZE = 4096;

void generate_rsa_keypair(const std::string& private_key_path, const std::string& public_key_path, const std::string& password) {
    // Initialize the context for key generation
    PUBLIC_KEY_CONTEXT ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        throw std::runtime_error("Failed to create keygen context.");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize keygen context.");
    }

    // Set the RSA key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 4096) <= 0) {
        throw std::runtime_error("Failed to set RSA key size.");
    }

    // Generate key structure
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0) {
        throw std::runtime_error("Failed to generate key pair.");
    }
    PRIVATE_KEY pkey(raw_pkey);

    // Save the Private Key
    KEY_BIO priv_bio(BIO_new_file(private_key_path.c_str(), "w"));
    if (!priv_bio) {
        throw std::runtime_error("Failed to create private key file.");
    }

    if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(), (unsigned char*)password.c_str(), password.length(), nullptr, nullptr) <= 0) {
        throw std::runtime_error("Failed to write private key to file.");
    }

    // Save the Public Key
    KEY_BIO pub_bio(BIO_new_file(public_key_path.c_str(), "w"));
    if (!pub_bio)
        throw std::runtime_error("Failed to create public key file.");

    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0)
        throw std::runtime_error("Failed to write public key to file.");
}

// Load Public Key from file
PRIVATE_KEY load_public_key(const std::string& path) {
    static std::unordered_map<std::string, std::shared_ptr<EVP_PKEY>> cache;
    static std::mutex cache_mutex;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(path);
        if (it != cache.end()) {
            EVP_PKEY_up_ref(it->second.get());
            return PRIVATE_KEY(it->second.get());
        }
    }

    KEY_BIO file(BIO_new_file(path.c_str(), "r"));
    if (!file) 
        throw std::runtime_error("Cannot open public key file.");

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!pkey) 
        throw std::runtime_error("Failed to read public key.");

    std::shared_ptr<EVP_PKEY> shared_pkey(pkey, EVP_PKEY_free);

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(path);
        if (it != cache.end()) {
            // Another thread already cached it, use theirs
            EVP_PKEY_up_ref(it->second.get());
            return PRIVATE_KEY(it->second.get());
        } else {
            cache[path] = shared_pkey;
            EVP_PKEY_up_ref(shared_pkey.get());
            return PRIVATE_KEY(shared_pkey.get());
        }
    }
}

// Load Private Key from file
PRIVATE_KEY load_private_key(const std::string& path, const std::string& password) {
    KEY_BIO file(BIO_new_file(path.c_str(), "r"));

    if (!file)
        throw std::runtime_error("Cannot open private key file.");
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(file.get(), nullptr, nullptr, (void*)password.c_str());
    if (!pkey)
        throw std::runtime_error("Failed to read private key.");

    return PRIVATE_KEY(pkey);
}

// HELPER: RSA Encrypt AES Key
std::vector<unsigned char> rsa_encrypt_aes_key(const unsigned char aes_key[32], EVP_PKEY* pub_key) {
    PUBLIC_KEY_CONTEXT rsa_ctx(EVP_PKEY_CTX_new(pub_key, nullptr));
    if (!rsa_ctx || EVP_PKEY_encrypt_init(rsa_ctx.get()) <= 0) 
        throw std::runtime_error("RSA init failed.");

    size_t encrypted_key_len = 0;
    if (EVP_PKEY_encrypt(rsa_ctx.get(), nullptr, &encrypted_key_len, aes_key, 32) <= 0) {
        throw std::runtime_error("RSA encrypted key size calculation failed.");
    }
    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    if (EVP_PKEY_encrypt(rsa_ctx.get(), encrypted_key.data(), &encrypted_key_len, aes_key, 32) <= 0)
        throw std::runtime_error("RSA encryption failed.");
    return encrypted_key;
}

// HELPER: AES Stream Encrypt
void aes_encrypt_stream(std::ifstream& in_file, std::ofstream& out_file, const unsigned char aes_key[32], const unsigned char iv[16]) {
    CIPHER_CONTEXT aes_ctx(EVP_CIPHER_CTX_new());
    if (!aes_ctx || EVP_EncryptInit_ex(aes_ctx.get(), EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1) {
        throw std::runtime_error("AES init failed.");
    }

    std::vector<char> in_buf(BUFFER_SIZE);
    std::vector<unsigned char> out_buf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;

    while (in_file.read(in_buf.data(), BUFFER_SIZE) || in_file.gcount() > 0) {
        if (EVP_EncryptUpdate(aes_ctx.get(), out_buf.data(), &out_len,
                               reinterpret_cast<const unsigned char*>(in_buf.data()), in_file.gcount()) != 1) {
            throw std::runtime_error("AES update failed.");
        }
        out_file.write(DATA_WRITE(out_buf.data()), out_len);
    }

    if (EVP_EncryptFinal_ex(aes_ctx.get(), out_buf.data(), &out_len) != 1)
        throw std::runtime_error("AES final failed.");
    out_file.write(DATA_WRITE(out_buf.data()), out_len);
}

// HELPER: YubiKey Decrypt AES Key
std::vector<unsigned char> yubikey_decrypt_aes_key(ykpiv_state* state, const std::vector<unsigned char>& encrypted_key) {
    std::vector<unsigned char> aes_key(256); // Max possible RSA decrypted length
    size_t aes_key_len = aes_key.size();

    ykpiv_rc rc = ykpiv_decipher_data(state, encrypted_key.data(), encrypted_key.size(), aes_key.data(), &aes_key_len, YKPIV_ALGO_RSA2048, YKPIV_KEY_KEYMGM);

    if (rc != YKPIV_OK) {
        throw std::runtime_error("YubiKey decipher failed. Key might be wrong or corrupted. Error: " + std::to_string(rc));
    }

    std::vector<unsigned char> unpadded_aes_key(256);
    int unpadded_len = RSA_padding_check_PKCS1_type_2(unpadded_aes_key.data(), unpadded_aes_key.size(), aes_key.data(), aes_key_len, 256);
    if (unpadded_len == -1) {
        throw std::runtime_error("Failed to unpad deciphered data.");
    }

    std::vector<unsigned char> final_aes_key(unpadded_aes_key.data(), unpadded_aes_key.data() + unpadded_len);

    if (final_aes_key.size() != 32)
        throw std::runtime_error("Decryption produced an unexpected AES key size.");

    return final_aes_key;
}

// HELPER: AES Stream Decrypt
void aes_decrypt_stream(std::ifstream& input_file, std::ofstream& output_file, const std::vector<unsigned char>& aes_key, const unsigned char iv[16]) {
    CIPHER_CONTEXT aes_ctx(EVP_CIPHER_CTX_new());
    if (!aes_ctx || EVP_DecryptInit_ex(aes_ctx.get(), EVP_aes_256_cbc(), nullptr, aes_key.data(), iv) != 1) {
        throw std::runtime_error("AES decrypt init failed.");
    }

    std::vector<char> input_buf(BUFFER_SIZE);
    std::vector<unsigned char> output_buf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;

    while (input_file.read(input_buf.data(), BUFFER_SIZE) || input_file.gcount() > 0) {
        if (EVP_DecryptUpdate(aes_ctx.get(), output_buf.data(), &out_len,
                               reinterpret_cast<const unsigned char*>(input_buf.data()), input_file.gcount()) != 1) {
            throw std::runtime_error("AES decrypt update failed.");
        }
        output_file.write(DATA_READ(output_buf.data()), out_len);
    }

    if (EVP_DecryptFinal_ex(aes_ctx.get(), output_buf.data(), &out_len) != 1) {
        throw std::runtime_error("Decryption integrity check failed.");
    }
    output_file.write(DATA_READ(output_buf.data()), out_len);
}

// ENCRYPTION
void hybrid_encrypt(const std::string& input_path, const std::string& output_path, EVP_PKEY* pub_key) {
    // Generate ephemeral AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        throw std::runtime_error("Failed to generate random AES key/IV.");
    }

    // Encrypt the AES key using the RSA Public Key
    std::vector<unsigned char> encrypted_key = rsa_encrypt_aes_key(aes_key, pub_key);

    // Open file streams
    std::ifstream in_file(input_path, std::ios::binary);
    std::ofstream out_file(output_path, std::ios::binary);
    if (!in_file || !out_file) throw std::runtime_error("File stream error.");

    // Write metadata header
    uint32_t key_len_header = static_cast<uint32_t>(encrypted_key.size());
    out_file.write(DATA_WRITE(&key_len_header), sizeof(key_len_header));
    out_file.write(DATA_WRITE(encrypted_key.data()), encrypted_key.size());
    out_file.write(DATA_WRITE(iv), sizeof(iv));

    // Stream encrypt the actual file data via AES
    aes_encrypt_stream(in_file, out_file, aes_key, iv);
}

// DECRYPTION
void hybrid_decrypt(const std::string& input_path, const std::string& output_path) {
    ykpiv_state* raw_state = nullptr;
    if (ykpiv_init(&raw_state, 0) != YKPIV_OK) {
        throw std::runtime_error("Failed to initialize YubiKey state for decryption.");
    }
    YKPIV_STATE state(raw_state);

    if (ykpiv_connect(state.get(), nullptr) != YKPIV_OK) {
        throw std::runtime_error("Failed to connect to YubiKey for decryption. Is it plugged in?");
    }

    std::ifstream input_file(input_path, std::ios::binary);
    std::ofstream output_file(output_path, std::ios::binary);
    if (!input_file || !output_file) throw std::runtime_error("File stream error.");

    // Read metadata header
    uint32_t encrypted_key_len = 0;
    input_file.read(DATA_READ(&encrypted_key_len), sizeof(encrypted_key_len));

    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    input_file.read(DATA_READ(encrypted_key.data()), encrypted_key_len);

    unsigned char iv[16]{};
    input_file.read(DATA_READ(iv), sizeof(iv));

    // Decrypt the secret AES key using the YubiKey
    std::string pin;
    std::cout << "Enter YubiKey PIN: ";
    std::cin >> pin;
    int tries = 0;
    if (ykpiv_verify(state.get(), pin.c_str(), &tries) != YKPIV_OK) {
        throw std::runtime_error("Failed to verify YubiKey PIN for decryption. Remaining tries: " + std::to_string(tries));
    }

    std::vector<unsigned char> aes_key = yubikey_decrypt_aes_key(state.get(), encrypted_key);

    // Stream decrypt the file data using the recovered AES key
    aes_decrypt_stream(input_file, output_file, aes_key, iv);
}

int main() {
    try {
        const std::string input_path = "important_data.txt";
        const std::string encrypted_path = "important_data.enc";
        const std::string restored_path = "restored_test.txt";

        std::ifstream input_check(input_path, std::ios::binary);
        if (!input_check) {
            throw std::runtime_error("Cannot open file.");
        }
        
        std::cout << "Getting YubiKey public key...\n";
        auto yk_pub_key = get_yubikey_public_key();

        std::cout << "Encrypting file with YubiKey public key...\n";
        hybrid_encrypt(input_path, encrypted_path, yk_pub_key.get());

        std::cout << "Decrypting file with YubiKey...\n";
        hybrid_decrypt(encrypted_path, restored_path);

        std::cout << "Done! Verify '" << restored_path << "' matching original inputs.\n";
    } catch (const std::exception& e) {
        std::cerr << "Pipeline failure: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
