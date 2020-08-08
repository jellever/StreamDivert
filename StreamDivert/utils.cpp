#include "stdafx.h"
#include "utils.h"
#include <vector>

HANDLE msgLock = CreateMutex(NULL, FALSE, NULL);

void message(const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	WaitForSingleObject(msgLock, INFINITE);
	vfprintf(stderr, msg, args);
	putc('\n', stderr);
	ReleaseMutex(msgLock);
	va_end(args);
}

void joinStr(const std::vector<std::string>& v, std::string& c, std::string& s)
{
	for (std::vector<std::string>::const_iterator p = v.begin();
		p != v.end(); ++p) {
		s += *p;
		if (p != v.end() - 1)
			s += c;
	}
}

void joinStr(const std::set<std::string>& v, std::string& c, std::string& s)
{
	std::vector<std::string> output(v.begin(), v.end());
	return joinStr(output, c, s);
}

std::string GetApplicationExecutablePath()
{
	char buffer[MAX_PATH];
	DWORD stat = GetModuleFileNameA(NULL, &buffer[0], sizeof(buffer));
	return std::string(&buffer[0]);
}
