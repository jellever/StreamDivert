#include "stdafx.h"
#include "config.h"
#include "utils.h"
#include <iostream>
#include <fstream>


RelayConfig LoadConfig(std::string path)
{
	RelayConfig result;
	std::ifstream ifs((path));
	std::string line;	

	while (std::getline(ifs, line))
	{		
		DWORD localPort = 0;
		char srcAddr[200] = { 0 };
		char dstAddr[200] = { 0 };
		DWORD dstPort = 0;

		int match = sscanf_s(line.c_str(), "%u %s -> %[^\:]:%ul", &localPort, &srcAddr[0], _countof(srcAddr), &dstAddr[0], _countof(dstAddr), &dstPort);
		if (match == 4)
		{
			RelayProxy& proxy = result.proxies[localPort];
			RelayEntry entry;
			proxy.localPort = localPort;
			entry.srcAddr = IpAddr(srcAddr);
			entry.forwardAddr = IpAddr(dstAddr);
			entry.forwardPort = dstPort;
			proxy.relayEntries.push_back(entry);			
		}		
	}
	return result;
}
