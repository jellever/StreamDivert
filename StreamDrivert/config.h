#pragma once
#include <windows.h>
#include "ipaddr.h"
#include <vector>
#include <map>


struct InboundRelayEntry
{
	IpAddr srcAddr;
	IpAddr forwardAddr;
	UINT16 forwardPort;
};

struct InboundRelayProxy
{
	std::string protocol;
	UINT16 localPort;
	std::vector<InboundRelayEntry> relayEntries;
};

struct OutboundRelayEntry
{
	std::string protocol;
	IpAddr dstAddr;
	UINT16 dstPort;
	IpAddr forwardAddr;
	UINT forwardPort;
};

struct OutboundRelayProxy
{
	std::vector<OutboundRelayEntry> relayEntries;
};

struct RelayConfig
{
	std::map<UINT16, InboundRelayProxy> inboundTCPProxies;
	std::map<UINT16, InboundRelayProxy> inboundICMPProxies;
	std::map<UINT16, InboundRelayProxy> inboundUDPProxies;
	OutboundRelayProxy outboundProxy;
};


RelayConfig LoadConfig(std::string path);
