#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <sodium.h>
#include <sqlite3.h>

class Vault {
    private:
        sqlite3* db = nullptr;
    public:
        void init(std::string vaultPath); //acts as constructor
        void add();
        ~Vault(); // Destructor to close DB
};

#endif