#pragma once
#include <vector>
#include <set>

void vmessage(const char* msg, va_list args);
void verror(std::string msg, va_list args);
void vwarning(std::string msg, va_list args);
void vinfo(std::string msg, va_list args);
void vdebug(std::string msg, va_list args);


void error(std::string msg, ...);
void warning(std::string msg, ...);
void info(std::string msg, ...);
void debug(std::string msg, ...);

void joinStr(const std::vector<std::string>& v, std::string& c, std::string& s);
void joinStr(const std::set<std::string>& v, std::string& c, std::string& s);

std::string GetApplicationExecutablePath();
char* basename(char* filepath);