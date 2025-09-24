#include "Parser.h"
#include <sstream>
#include <iostream>

Parser::Parser() {
    command_table = {
        {"init", [this](const std::vector<std::string>& cmd) {handle_add(cmd); }},
        {"add", [this](const std::vector<std::string>& cmd) {handle_add(cmd); }}
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

    //add case insensitivity?
    std::string baseCommand = cmd[0];
    auto it = command_table.find(baseCommand);
    if (it != command_table.end()) {
        it->second(cmd); //go to coresponding command function, passing in cmd to it
    } else {
        std::string response = "-ERR unknown command";
        std::cout << response << std::endl;
    }    
}

void Parser::handle_init(const std::vector<std::string> & cmd) {
    
}

void Parser::handle_add( const std::vector<std::string> & cmd) {

}