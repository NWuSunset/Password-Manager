#include "Vault.h"
#include "utils.h"
#include <iostream>

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

    // generate salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    //derive master key
    auto key = derive_key(m_pwd, salt);
    std::string plaintext = "a secret password";
    auto blob = encrypt(key, plaintext, "vault-v1"); 

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

void Vault::add() {

}

Vault::~Vault() {
    if (db) {
        sqlite3_close(db);
    }
}