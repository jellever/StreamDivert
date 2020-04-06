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
		UINT16 localPort = 0;
		char srcAddr[200] = { 0 };
		char dstAddr[200] = { 0 };		
		UINT16 dstPort = 0;
		char forwardAddr[200] = { 0 };
		UINT16 forwardPort = 0;

		int match = sscanf_s(line.c_str(), "< %hu:%s -> %[^\:]:%hu", &localPort, &srcAddr[0], _countof(srcAddr), &forwardAddr[0], _countof(forwardAddr), &forwardPort);
		if (match == 4)
		{
			InboundRelayProxy& proxy = result.inboundProxies[localPort];
			InboundRelayEntry entry;
			proxy.localPort = localPort;
			entry.srcAddr = IpAddr(srcAddr);
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = forwardPort;
			proxy.relayEntries.push_back(entry);			
		}
		else
		{
			match = sscanf_s(line.c_str(), "> %[^\:]:%hu -> %[^\:]:%hu", &dstAddr[0], _countof(dstAddr), &dstPort, &forwardAddr[0], _countof(forwardAddr), &forwardPort);
			if (match == 4)
			{
				OutboundRelayProxy& proxy = result.outboundProxy;
				OutboundRelayEntry entry;
				entry.dstAddr = IpAddr(dstAddr);
				entry.dstPort = dstPort;
				entry.forwardAddr = IpAddr(forwardAddr);
				entry.forwardPort = forwardPort;
				proxy.relayEntries.push_back(entry);
			}
		}
	}
	return result;
}
