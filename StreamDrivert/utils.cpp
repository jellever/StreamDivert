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

bool stringToIp(std::string ipStr, UINT32& result)
{
	char ipBytes[4];
	int fulfilled = sscanf_s(ipStr.c_str(), "%hhu.%hhu.%hhu.%hhu",
			&ipBytes[3], &ipBytes[2], &ipBytes[1], &ipBytes[0]);
	if (fulfilled != 4)
	{
		result = 0;
		return false;
	}
	result = ipBytes[0] | ipBytes[1] << 8 | ipBytes[2] << 16 | ipBytes[3] << 24;
	return true;
}

std::string ipToString(UINT32 ip)
{
	char ipAddr[16];
	snprintf(ipAddr, sizeof(ipAddr), "%u.%u.%u.%u"
		, (ip & 0xff000000) >> 24
		, (ip & 0x00ff0000) >> 16
		, (ip & 0x0000ff00) >> 8
		, (ip & 0x000000ff));

	return std::string(ipAddr);
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