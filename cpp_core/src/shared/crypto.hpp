#pragma once
#include <openssl/evp.h>
#include <string>
#include <vector>

EVP_PKEY* generate_rsa_keypair();
std::string get_public_key_pem(EVP_PKEY* pkey);
EVP_PKEY* load_public_key_from_string(const std::string& pem_string);

// --- NOVÉ FUNKCE ---
// Generování kryptograficky bezpečného symetrického klíče (32 bajtů pro AES-256)
std::vector<unsigned char> generate_symmetric_key(int length = 32);

// Zašifrování dat (symetrického klíče) pomocí veřejného RSA klíče
std::vector<unsigned char> rsa_encrypt(EVP_PKEY* pub_key, const std::vector<unsigned char>& data);

// Dešifrování dat pomocí privátního RSA klíče
std::vector<unsigned char> rsa_decrypt(EVP_PKEY* priv_key, const std::vector<unsigned char>& encrypted_data);

// Symetrické šifrování zprávy (AES-256-CBC)
std::vector<unsigned char> aes_encrypt(const std::string& plaintext, const std::vector<unsigned char>& key);

// Symetrické dešifrování zprávy (AES-256-CBC)
std::string aes_decrypt(const std::vector<unsigned char>& ciphertext_with_iv, const std::vector<unsigned char>& key);
