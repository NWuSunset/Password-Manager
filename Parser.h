#ifndef PARSER_H
#define PARSER_H

#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include "Vault.h"

class Parser {
    private:
        Vault& vault;
        std::unordered_map<std::string, std::function<void(const std::vector<std::string> &)>> command_table;
    public:
        Parser(Vault& vault);
        std::vector<std::string> parse(std::string);
        void executeCommand(std::vector<std::string> cmd);

        //cmd handlers 
        void handle_add(const std::vector<std::string> & cmd);
        void handle_init(const std::vector<std::string> & cmd);
};

#endif