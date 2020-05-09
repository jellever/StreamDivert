#pragma once
#include <vector>
#include <set>

void message(const char *msg, ...);


#define error(msg, ...)                         \
    do {                                        \
        message("[-] " msg, ## __VA_ARGS__); \
    } while (FALSE)
#define warning(msg, ...)                       \
    message("[!] " msg, ## __VA_ARGS__)

#define info(msg, ...)                       \
    message("[*] " msg, ## __VA_ARGS__)

void joinStr(const std::vector<std::string>& v, std::string& c, std::string& s);
void joinStr(const std::set<std::string>& v, std::string& c, std::string& s);
std::string ipToString(UINT32 ip);
bool stringToIp(std::string ipStr, UINT32& result);