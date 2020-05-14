#pragma once
#include <windows.h>
#include "ipaddr.h"
#include <vector>
#include <map>


struct InboundRelayEntry
{
	std::string protocol;
	UINT16 localPort;
	IpAddr srcAddr;
	IpAddr forwardAddr;
	UINT16 forwardPort;
};

struct OutboundRelayEntry
{
	std::string protocol;
	IpAddr dstAddr;
	UINT16 dstPort;
	IpAddr forwardAddr;
	UINT forwardPort;
};

struct RelayConfig
{
	std::vector<InboundRelayEntry> inboundRelayEntries;
	std::vector<OutboundRelayEntry> outboundRelayEntries;
};

RelayConfig LoadConfig(std::string path);
