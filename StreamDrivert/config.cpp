#include "stdafx.h"
#include "config.h"
#include "utils.h"
#include <iostream>
#include <fstream>

std::map<UINT16, InboundRelayProxy>* getProtocolInboundProxyMap(RelayConfig& cfg, std::string& proto)
{
	if (proto == "tcp")
	{
		return &cfg.inboundTCPProxies;
	}
	else if (proto == "udp")
	{
		return &cfg.inboundUDPProxies;
	}
	else if (proto == "icmp")
	{
		return &cfg.inboundICMPProxies;
	}
	return NULL;
}

RelayConfig LoadConfig(std::string path)
{
	RelayConfig result;
	std::ifstream ifs((path));
	std::string line;	

	while (std::getline(ifs, line))
	{
		char proto[200] = { 0 };
		UINT16 localPort = 0;
		char srcAddr[200] = { 0 };
		char dstAddr[200] = { 0 };		
		UINT16 dstPort = 0;
		char forwardAddr[200] = { 0 };
		UINT16 forwardPort = 0;

		int match = sscanf_s(line.c_str(), "%s < %hu %s -> %s %hu", &proto[0], _countof(proto), &localPort, &srcAddr[0], _countof(srcAddr), &forwardAddr[0], _countof(forwardAddr), &forwardPort);
		if (match == 5)
		{
			std::map<UINT16, InboundRelayProxy>* inboundProxyMap = getProtocolInboundProxyMap(result, std::string(proto));
			if (inboundProxyMap != NULL)
			{
				InboundRelayProxy& proxy = (*inboundProxyMap)[localPort];
				InboundRelayEntry entry;
				proxy.localPort = localPort;
				entry.srcAddr = IpAddr(srcAddr);
				entry.forwardAddr = IpAddr(forwardAddr);
				entry.forwardPort = forwardPort;
				proxy.relayEntries.push_back(entry);
			}
		}
		else
		{
			match = sscanf_s(line.c_str(), "%s > %s %hu -> %s %hu", &proto[0], _countof(proto), &dstAddr[0], _countof(dstAddr), &dstPort, &forwardAddr[0], _countof(forwardAddr), &forwardPort);
			if (match == 5)
			{
				OutboundRelayProxy& proxy = result.outboundProxy;
				OutboundRelayEntry entry;
				entry.protocol = std::string(proto);
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
