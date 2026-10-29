#include "crypto.hpp"
#include <openssl/rsa.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <vector>

EVP_PKEY* generate_rsa_keypair() {
    // 1. Vytvoříme kontext pro generování RSA klíčů
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "[CRYPTO] Chyba pri vytvareni kontextu pro klic.\n";
        return nullptr;
    }

    // 2. Inicializace generátoru
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri inicializaci generovani.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // 3. Nastavíme délku klíče na 2048 bitů (dnes standardní bezpečnost)
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri nastavovani delky klice.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // 4. Samotné vygenerování klíče
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri samotnem generovani klice.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Úklid dočasného kontextu (samotný klíč 'pkey' vracíme)
    EVP_PKEY_CTX_free(ctx);
    std::cout << "[CRYPTO] RSA klicovy par (2048 bit) uspesne vygenerovan!\n";
    return pkey;
}

std::string get_public_key_pem(EVP_PKEY* pkey) {
    // 1. Vytvoříme paměťový "soubor" (BIO)
    BIO* mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        std::cerr << "[CRYPTO] Chyba pri vytvareni pameti pro PEM.\n";
        return "";
    }

    // 2. Zapíšeme veřejnou část klíče do našeho paměťového BIO
    if (PEM_write_bio_PUBKEY(mem_bio, pkey) != 1) {
        std::cerr << "[CRYPTO] Chyba pri zapisu klice do PEM formatu.\n";
        BIO_free(mem_bio);
        return "";
    }

    // 3. Přečteme data z BIO a uložíme je do klasického C++ stringu
    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(mem_bio, &pem_data);
    std::string pem_string(pem_data, pem_len);

    // 4. Uklidíme paměť
    BIO_free(mem_bio);
    return pem_string;
}

EVP_PKEY* load_public_key_from_string(const std::string& pem_string) {
    // 1. Vytvoříme BIO "soubor" pouze pro čtení z našeho přijatého textu
    BIO* bio = BIO_new_mem_buf(pem_string.data(), pem_string.size());
    if (!bio) {
        std::cerr << "[CRYPTO] Chyba pri vytvareni BIO pro cteni klice.\n";
        return nullptr;
    }

    // 2. Řekneme OpenSSL, ať text přečte a složí z něj strukturu veřejného klíče
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        std::cerr << "[CRYPTO] Chyba pri parsovani verejneho klice z textu.\n";
    }

    // 3. Uklidíme BIO paměť
    BIO_free(bio);
    return pkey; // Vracíme hotový klíč (nebo nullptr v případě chyby)
}

std::vector<unsigned char> generate_symmetric_key(int length) {
    std::vector<unsigned char> key(length);
    // RAND_bytes zaručuje kryptograficky silnou náhodnost
    if (RAND_bytes(key.data(), length) != 1) {
        std::cerr << "[CRYPTO] Chyba pri generovani nahodnych bytu pro symetricky klic.\n";
        return {}; // Vrátíme prázdný vektor
    }
    return key;
}

std::vector<unsigned char> rsa_encrypt(EVP_PKEY* pub_key, const std::vector<unsigned char>& data) {
    // 1. Vytvoříme šifrovací kontext
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri inicializaci sifrovani.\n";
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 2. Nastavíme bezpečný OAEP padding (naprostý standard pro obranu proti útokům)
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri nastavovani OAEP paddingu.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 3. Zjistíme, jak velký bude zašifrovaný výstup (u 2048bit RSA to bude vždy 256 bajtů)
    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, data.data(), data.size()) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri zjistovani delky sifrovaneho textu.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 4. Samotné zašifrování
    std::vector<unsigned char> out(out_len);
    if (EVP_PKEY_encrypt(ctx, out.data(), &out_len, data.data(), data.size()) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri samotnem RSA sifrovani.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(out_len); // Zarovnání velikosti pro jistotu
    return out;
}

std::vector<unsigned char> rsa_decrypt(EVP_PKEY* priv_key, const std::vector<unsigned char>& encrypted_data) {
    // 1. Vytvoříme dešifrovací kontext
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri inicializaci desifrovani.\n";
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 2. Nastavíme stejný OAEP padding, jaký použil klient
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri nastavovani OAEP paddingu pro desifrovani.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 3. Zjistíme finální velikost dešifrovaných dat
    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, encrypted_data.data(), encrypted_data.size()) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri zjistovani delky desifrovaneho textu.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 4. Samotné dešifrování
    std::vector<unsigned char> out(out_len);
    if (EVP_PKEY_decrypt(ctx, out.data(), &out_len, encrypted_data.data(), encrypted_data.size()) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri samotnem RSA desifrovani.\n";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(out_len); // Zarovnání na přesnou délku (32 bajtů)
    return out;
}

std::vector<unsigned char> aes_encrypt(const std::string& plaintext, const std::vector<unsigned char>& key) {
    // 1. Vygenerujeme unikátní IV pro tuto konkrétní zprávu (16 bajtů)
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);

    // 2. Příprava OpenSSL kontextu pro AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    // 3. Samotné šifrování textu
    // Vytvoříme buffer, který musí být o něco větší (kvůli zarovnání bloků u AES)
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
    int ciphertext_len = len;

    // Dokončení šifrování (padding)
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len); // Ořízneme vektor na reálnou velikost dat
    EVP_CIPHER_CTX_free(ctx);

    // 4. Slepení do finálního balíčku: [ 16 bajtů IV ] + [ Šifrovaný text ]
    std::vector<unsigned char> result;
    result.reserve(iv.size() + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

std::string aes_decrypt(const std::vector<unsigned char>& ciphertext_with_iv, const std::vector<unsigned char>& key) {
    // Bezpečnostní kontrola - zpráva musí obsahovat minimálně 16 bajtů IV
    if (ciphertext_with_iv.size() < 16) return "";

    // 1. Rozdělení přijatého balíčku zpět na IV a samotný šifrovaný text
    std::vector<unsigned char> iv(ciphertext_with_iv.begin(), ciphertext_with_iv.begin() + 16);
    std::vector<unsigned char> ciphertext(ciphertext_with_iv.begin() + 16, ciphertext_with_iv.end());

    // 2. Příprava OpenSSL kontextu pro dešifrování
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    // 3. Dešifrování
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    // Pokud dešifrování selže (např. někdo změnil data po cestě nebo máme špatný klíč)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        std::cerr << "[CRYPTO] Chyba pri AES desifrovani (poskozena data?).\n";
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Vrátíme výsledek jako krásný čistý C++ string
    return std::string((char*)plaintext.data(), plaintext_len);
}
