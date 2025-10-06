#include <sodium.h>
#include <vector>
#include <string>
#include <iostream>
#include "Parser.h"
#include "Vault.h"

bool init_sodium() {
    if (sodium_init() < 0) return false;
    return true;
}



int main() {
    if (!init_sodium()) return 1;

    

    /*CLI arguments list:
        -init

    */
    Vault vault;
    Parser parser(vault);

    //parser.parse("pmgr init");
    //parser.parse("pmgr add --title testTitle --username testUsername --password testPassword");
   // parser.parse("pmgr list");
    while (true) {

    std::cout << "Enter args (make sure to use pmgr before commands): " << std::endl;
    //Command parser
    std::string request; //add an actual user request
    std::getline(std::cin, request);

    std::vector<std::string> command = parser.parse(request);
    if (command.size() >= 2 && command[0] == "pmgr" && command[1] == "quit") {
        std::cout << "Quitting" << std::endl;
        break;
    }

    parser.executeCommand(command);
    }


/*
    //Test salting and encrpytions
    if (!init_sodium()) return 1;

    std::string password = "the swift brown fox";
    // generate salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    auto key = derive_key(password, salt);
    std::string plaintext = "Test Password";

    auto blob = encrypt(key, plaintext, "vault-v1"); 

    // to store: keep salt, blob.nonce, blob.ct
    std::cout << "Encrypted size: " << blob.ct.size() << " nonce size " << blob.nonce.size() << "\n";

    // Now decrypt
    auto recovered = decrypt(key, blob, "vault-v1");
    std::cout << "Recovered plaintext: " << recovered << "\n"; */
    return 0;
}


