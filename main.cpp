#include <cstdint>
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

#define DATA_WRITE(data) reinterpret_cast<const char*>(data)
#define DATA_READ(data) reinterpret_cast<char*>(data)

constexpr size_t BUFFER_SIZE = 4096;
// RAII
struct PKEYDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct CTXDeleter  { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct CipherDeleter { void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); } };
struct BIODeleter { void operator()(BIO* b) const { BIO_free_all(b); } };

typedef std::unique_ptr<EVP_PKEY, PKEYDeleter> PRIVATE_KEY;
typedef std::unique_ptr<EVP_PKEY_CTX, CTXDeleter> PUBLIC_KEY_CONTEXT;
typedef std::unique_ptr<BIO, BIODeleter> KEY_BIO;
typedef std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter> CIPTHER_CONTEXT;

void generate_rsa_keypair(const std::string& private_key_path, const std::string& public_key_path) {
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
    // TODO: use private key with password
    if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
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
    KEY_BIO file(BIO_new_file(path.c_str(), "r"));
    if (!file) 
        throw std::runtime_error("Cannot open public key file.");

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!pkey) 
        throw std::runtime_error("Failed to read public key.");
    return PRIVATE_KEY(pkey);
}

// Load Private Key from file
PRIVATE_KEY load_private_key(const std::string& path) {
    KEY_BIO file(BIO_new_file(path.c_str(), "r"));

    if (!file)
        throw std::runtime_error("Cannot open private key file.");
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(file.get(), nullptr, nullptr, nullptr);
    if (!pkey)
        throw std::runtime_error("Failed to read private key.");

    return PRIVATE_KEY(pkey);
}

// ENCRYPTION
void hybrid_encrypt(const std::string& input_path, const std::string& output_path, const std::string& pub_key_path) {
    auto pub_key = load_public_key(pub_key_path);

    // Generate ephemeral AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        throw std::runtime_error("Failed to generate random AES key/IV.");
    }

    // Encrypt the AES key using the RSA Public Key
    PUBLIC_KEY_CONTEXT rsa_ctx(EVP_PKEY_CTX_new(pub_key.get(), nullptr));
    if (!rsa_ctx || EVP_PKEY_encrypt_init(rsa_ctx.get()) <= 0) 
        throw std::runtime_error("RSA init failed.");

    size_t encrypted_key_len = 0;
    if (EVP_PKEY_encrypt(rsa_ctx.get(), nullptr, &encrypted_key_len, aes_key, sizeof(aes_key)) <= 0) {
        throw std::runtime_error("RSA encrypted key size calculation failed.");
    }
    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    if (EVP_PKEY_encrypt(rsa_ctx.get(), encrypted_key.data(), &encrypted_key_len, aes_key, sizeof(aes_key)) <= 0)
        throw std::runtime_error("RSA encryption failed.");

    // Open file streams
    std::ifstream in_file(input_path, std::ios::binary);
    std::ofstream out_file(output_path, std::ios::binary);
    if (!in_file || !out_file) throw std::runtime_error("File stream error.");

    // Write metadata header
    uint32_t key_len_header = static_cast<uint32_t>(encrypted_key_len);
    out_file.write(DATA_WRITE(&key_len_header), sizeof(key_len_header));
    out_file.write(DATA_WRITE(encrypted_key.data()), encrypted_key_len);
    out_file.write(DATA_WRITE(iv), sizeof(iv));

    // Stream encrypt the actual file data via AES
    CIPTHER_CONTEXT aes_ctx(EVP_CIPHER_CTX_new());
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

// DECRYPTION
void hybrid_decrypt(const std::string& input_path, const std::string& output_path, const std::string& priv_key_path) {
    auto priv_key = load_private_key(priv_key_path);

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

    // Decrypt the secret AES key using the RSA Private Key
    PUBLIC_KEY_CONTEXT rsa_ctx(EVP_PKEY_CTX_new(priv_key.get(), nullptr));
    if (!rsa_ctx || EVP_PKEY_decrypt_init(rsa_ctx.get()) <= 0) throw std::runtime_error("RSA decrypt init failed.");

    size_t aes_key_len = 0;
    if (EVP_PKEY_decrypt(rsa_ctx.get(), nullptr, &aes_key_len, encrypted_key.data(), encrypted_key_len) <= 0)
        throw std::runtime_error("RSA decrypted key size calculation failed.");

    std::vector<unsigned char> aes_key(aes_key_len);
    if (EVP_PKEY_decrypt(rsa_ctx.get(), aes_key.data(), &aes_key_len, encrypted_key.data(), encrypted_key_len) <= 0) {
        throw std::runtime_error("RSA decryption failed. Key might be wrong or corrupted.");
    }
    if (aes_key_len != 32) 
        throw std::runtime_error("RSA decryption produced an unexpected AES key size.");

    aes_key.resize(aes_key_len);

    // Stream decrypt the file data using the recovered AES key
    CIPTHER_CONTEXT aes_ctx(EVP_CIPHER_CTX_new());
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

int main() {
    try {
        // Setup a test file
        std::ofstream f("important_data.txt"); 
        f << "Top secret hybrid structural data streams.";
        
        std::cout << "Generating RSA-4096 key pair...\n";
        generate_rsa_keypair("private.pem", "public.pem");
        std::cout << "Success! Saved 'private.pem' and 'public.pem'.\n";

        std::cout << "Encrypting file with public key...\n";
        hybrid_encrypt("important_data.txt", "important_data.enc", "public.pem");

        std::cout << "Decrypting file with private key...\n";
        hybrid_decrypt("important_data.enc", "restored_data.txt", "private.pem");

        std::cout << "Done! Verify 'restored_data.txt' matching original inputs.\n";
    } catch (const std::exception& e) {
        std::cerr << "Pipeline failure: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
