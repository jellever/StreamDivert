#pragma once
#include <windows.h>
#include "ipaddr.h"
#include <vector>
#include <map>


struct RelayEntry
{
	IpAddr srcAddr;
	IpAddr forwardAddr;
	UINT16 forwardPort;
};

struct RelayProxy
{
	UINT16 localPort;
	std::vector<RelayEntry> relayEntries;
};

struct RelayConfig
{
	std::map<UINT16, RelayProxy> proxies;
};


RelayConfig LoadConfig(std::string path);
