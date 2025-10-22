#include "Vault.h"
#include "utils.h"
#include <iostream>

#define VAULTS_PATH = std::string(getenv("HOME"))  + "/pmgr_vaults"

void Vault::init(std::string vaultPath) {
    if (sqlite3_open(vaultPath.c_str(), &db) != SQLITE_OK) { //open the sqlite database 
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        db = nullptr;
        return;
    }
    //sql statement
    //passwords table
    const char* sql = "CREATE TABLE IF NOT EXISTS passwords ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "service TEXT NOT NULL,"
                    "username TEXT NOT NULL,"
                    "password BLOB NOT NULL,"
                    "website TEXT NOT NULL,"
                    "salt BLOB NOT NULL,"
                    "nonce BLOB NOT NULL);";
    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) { //execute sql statement
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return;
    }

     // Create vault_meta table for master key verification
    const char* sql_meta = "CREATE TABLE IF NOT EXISTS vault_meta ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "salt BLOB NOT NULL,"
                          "nonce BLOB NOT NULL,"
                          "ct BLOB NOT NULL);";
    if (sqlite3_exec(db, sql_meta, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return;
    }

    std::cout << "Enter master password: " << std::endl;
    std::string m_pwd;
    std::getline(std::cin, m_pwd);
    setMasterPassword(m_pwd);

    // generate salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    //derive master key
    auto key = derive_key(m_pwd, salt);
    std::string plaintext = "a secret password";
    Ciphertext blob = encrypt(key, plaintext, "vault-v1"); 

    sqlite3_stmt* stmt;
    const char* insert_sql = "INSERT INTO vault_meta (salt, nonce, ct) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, salt.data(), salt.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, blob.nonce.data(), blob.nonce.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, blob.ct.data(), blob.ct.size(), SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Prepare failed: " << sqlite3_errmsg(db) << std::endl;
    }
    std::cout << "Vault initialized and encrypted with master password.\n";
}

void Vault::add(std::string service, std::string username, std::string password, std::string website) {
    std::cout << service << username << password << website << std::endl;
    
    //encrypt before storing
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    auto key = derive_key(getMasterPassword(), salt);
    auto blob = encrypt(key, password, service);
    
    const char* sql = "INSERT INTO passwords (service, username, password, website, salt, nonce) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, blob.ct.data(), blob.ct.size(), SQLITE_STATIC); //encrpyted password
        sqlite3_bind_blob(stmt, 4, salt.data(), salt.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 5, blob.nonce.data(), blob.nonce.size(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, website.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Prepare failed: " << sqlite3_errmsg(db) << std::endl;
    }
    std::cout << "Sucessfully added entry into vault"  << std::endl;
}

void Vault::open(std::string vaultPath) {
    std::cout << vaultPath << std::endl;

    // Open existing database
    if (sqlite3_open(vaultPath.c_str(), &db) != SQLITE_OK) { //check if database exists
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        db = nullptr;
        return;
    }

    // Retrieve salt, nonce, and ciphertext from vault_meta
    const char* sql = "SELECT salt, nonce, ct FROM vault_meta LIMIT 1;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) { //prepare sql statement
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) { //if we don't find the correct metadata for the vault
        std::cerr << "No vault metadata found. Initialize vault first." << std::endl;
        sqlite3_finalize(stmt);
        return;
    }

    // Extract salt, nonce, ciphertext
    const unsigned char* salt = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 0));
    int salt_size = sqlite3_column_bytes(stmt, 0);
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));
    int nonce_size = sqlite3_column_bytes(stmt, 1);
    const unsigned char* ct = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 2));
    int ct_size = sqlite3_column_bytes(stmt, 2);

    std::vector<unsigned char> salt_vec(salt, salt + salt_size); //assign bytes to vecotrs 
    Ciphertext blob;
    blob.nonce = std::vector<unsigned char>(nonce, nonce + nonce_size);
    blob.ct = std::vector<unsigned char>(ct, ct + ct_size);
    
    sqlite3_finalize(stmt);

    // Prompt for master password
    std::cout << "Enter master password: " << std::endl;
    std::string m_pwd;
    std::getline(std::cin, m_pwd);

    // Derive key and try to decrypt
    auto key = derive_key(m_pwd, salt_vec);
    
    //Compare master password
    try {
        std::string decrypted = decrypt(key, blob, "vault-v1");
        if (decrypted == "a secret password") { //if the decrypted message is this plaintext, then the master password was correct
            std::cout << "Vault unlocked successfully!" << std::endl;
            setMasterPassword(m_pwd);
        } else {
            std::cerr << "Incorrect master password." << std::endl;
            sqlite3_close(db);
            db = nullptr;
        }
    } catch (...) {
        std::cerr << "Incorrect master password." << std::endl;
        sqlite3_close(db);
        db = nullptr;
    }
}

void Vault::list() {
    const char* sql = "SELECT * FROM passwords;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string service = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
            std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));

            //decrypt password
            const unsigned char* ct = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 3));
            int ct_size = sqlite3_column_bytes(stmt, 3);
            const unsigned char* salt = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 4));
            int salt_size = sqlite3_column_bytes(stmt, 4);
            const unsigned char* nonce = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 5));
            int nonce_size = sqlite3_column_bytes(stmt, 5);

            std::string website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));


            std::vector<unsigned char> salt_vector(salt, salt+salt_size);
            auto key = derive_key(getMasterPassword(), salt_vector);
        
            Ciphertext blob;
            blob.ct = std::vector<unsigned char>(ct, ct+ ct_size);
            blob.nonce = std::vector<unsigned char>(nonce, nonce + nonce_size);

            std::string password;
            try {
                password = decrypt(key, blob, service);
            } catch (...) {
                password = "decryption failed";
            }

            std::cout << "Service: " << service 
            << "\nUsername: " << username 
            << "\nPassword: " << password 
            << "\nWebsite: " << website << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Prepare failed " << sqlite3_errmsg(db) << std::endl;
    }   
}

void Vault::setMasterPassword(const std::string& pwd) {
    master_password = pwd;
}
std::string  Vault::getMasterPassword() {
    return master_password;
}

Vault::~Vault() {
    if (db) {
        sqlite3_close(db);
    }
}