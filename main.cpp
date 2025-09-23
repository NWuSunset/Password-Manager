#include <sodium.h>
#include <vector>
#include <string>
#include <iostream>

struct Ciphertext{
    
};

int main() {

    //init : create salt, derive key, create empty vault, encrpy + write file
    std::string password = "the swift brown fox"; //for salt 
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);

    randombytes_buf(salt.data(), salt.size());

    auto key = derive_key(password, salt); 

    std::string plaintext  = "Test Password";

    auto blob = encrypt(key, plaintext);

    return 0;
}

std::vector<unsigned char> derive_key(std::string password, std::vector<unsigned char> salt)

Ciphertext encrypt(std::vector<unsigned char> key,  std::string plaintext) {
    Ciphertext output;
    
}


