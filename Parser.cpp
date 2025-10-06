#include "Parser.h"
#include <sstream>
#include <iostream>

Parser::Parser(Vault& v) : vault(v) {
    command_table = {
        {"init", [this](const std::vector<std::string>& cmd) {handle_init(cmd); }},
        {"add", [this](const std::vector<std::string>& cmd) {handle_add(cmd); }},
         {"list", [this](const std::vector<std::string>& cmd) {handle_list(cmd); }}
    };
}

//takes input and tokenizes 
std::vector<std::string> Parser::parse(std::string input) {
 std::vector<std::string> res;
 std::istringstream iss(input);
 std::string token;

 while (iss >> token) {
    res.push_back(token);
 }

 return res;
}

void Parser::executeCommand(std::vector<std::string> cmd) {
    if (cmd.empty()) {
        std::string response = "-ERR empty command";
        std::cout << response << std::endl;
    }

    
    if (cmd[0] != "pmgr") {
        std::string response = "-ERR command must start with 'pmgr'";
        std::cout << response << std::endl;
    } 

    if (cmd.size() < 2) {
        std::string response = "-ERR missing subcommand";
        std::cout << response << std::endl;
        return;
    } 

    //add case insensitivity?
    std::string baseCommand = cmd[1];
    auto it = command_table.find(baseCommand);
    if (it != command_table.end()) {
        it->second(cmd); //go to coresponding command function, passing in cmd to it
    } else {
        std::string response = "-ERR unknown command";
        std::cout << response << std::endl;
    }    
}

void Parser::handle_init(const std::vector<std::string> & cmd) {
    std::string defaultVaultPath = std::string(getenv("HOME")) + "/.password_manager_vault.db";
    std::string vaultPath;

    if (cmd.size() > 2 && !cmd[2].empty()) {
    vaultPath = cmd[2]; //vault path should be directly after init (subject to change)
    } else {
        vaultPath = defaultVaultPath;
    }
    vault.init(vaultPath);
}

void Parser::handle_add( const std::vector<std::string> & cmd) {
    //adding ex: *pmgr add --service "Bank" --username "me" --password "1234"
    /*
        Flags to add: 
            --service
            --username
            --password
            --website URL (defaults to none if left blank)
    */
   std::unordered_map<std::string, std::string> args;
   for (size_t i = 2; i < cmd.size(); i++) {
    if (cmd[i].rfind("--", 0) == 0 && i + 1 < cmd.size()) { //if you find an argument flag (like --service)
        args[cmd[i]] = cmd[i+1]; //the service is the next word  
        ++i;
    }
   }
    std::string service = args["--service"];
    std::string username = args["--username"];
    std::string password = args["--password"];
    std::string website = args.count("--website") ? args["--website"] : "";
    
    vault.add(service, username, password, website);
}

void Parser::handle_list(const std::vector<std::string>& cmd) {
    vault.list();
}