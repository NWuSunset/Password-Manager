#include <vector>
#include <sodium.h>
#include <string>
#include <iostream>

// Derive key from password using libsodium crypto_pwhash (Argon2id)
std::vector<unsigned char> derive_key(const std::string &password, const std::vector<unsigned char> &salt) {
    const size_t KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
    std::vector<unsigned char> key(KEY_LEN);

    // Choose opslimit & memlimit 
    unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    if (crypto_pwhash(key.data(), KEY_LEN,
                      password.c_str(), password.size(),
                      salt.data(),
                      opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id derivation failed (not enough memory?)");
    }
    return key;
}

struct Ciphertext {
    std::vector<unsigned char> nonce; //number used once
    std::vector<unsigned char> ct; //ciphertext
};
//aad = auditional auth data
Ciphertext encrypt(const std::vector<unsigned char> &key, const std::string &plaintext, const std::string &aad = "") {
    Ciphertext out;
    out.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES); //allocate space for nonce
    randombytes_buf(out.nonce.data(), out.nonce.size()); //fill nonce

    //allocate ciphertext space
    out.ct.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len;

    //core encryption
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.ct.data(), &ct_len,
        (const unsigned char*)plaintext.data(), plaintext.size(),
        (const unsigned char*)aad.data(), aad.size(),
        nullptr, // no secret nonce
        out.nonce.data(),
        key.data()
    );
    out.ct.resize(ct_len);
    return out;
}

std::string decrypt(const std::vector<unsigned char> &key, const Ciphertext &blob, const std::string &aad = "") {
    std::vector<unsigned char> decrypted(blob.ct.size());
    unsigned long long decrypted_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            blob.ct.data(), blob.ct.size(),
            (const unsigned char*)aad.data(), aad.size(),
            blob.nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("Decryption failed: MAC check failed");
    }
    return std::string((char*)decrypted.data(), decrypted_len);
}