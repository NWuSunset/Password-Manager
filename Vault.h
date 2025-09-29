#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <sodium.h>
#include <sqlite3.h>

class Vault {
    private:
        sqlite3* db = nullptr;
        std::string master_password;
    public:
        void setMasterPassword(const std::string& pwd);
        std::string getMasterPassword();
        void init(std::string vaultPath); //acts as constructor
        void add(std::string title, std::string username, std::string password, std::string webstie);
        void list();
        ~Vault(); // Destructor to close DB
};

#endif