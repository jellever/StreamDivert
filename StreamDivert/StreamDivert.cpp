// StreamDivert.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <future>
#include "StreamDivert.h"
#include "InboundTCPDivertProxy.h"
#include "InboundUDPDivertProxy.h"
#include "InboundICMPDivertProxy.h"
#include "OutboundDivertProxy.h"
#include "utils.h"
#include "config.h"
#include "WindowsFirewall.h"
#include "SocksProxyServer.h"

// Global Variables:
HINSTANCE hInst;                                // current instance
/*
* Lock to sync output.
*/


int __cdecl main(int argc, char **argv)
{
	bool modifyFW = false;
	if (argc < 2)
	{
		error("No config file was specified!");
		exit(EXIT_FAILURE);
	}
	if (argc == 3 && std::string(argv[2]) == "-f")
	{
		modifyFW = true;
	}
	std::string cfgPath = argv[1];

	if (modifyFW)
	{
		info("Modifying firewall..");
		WindowsFirewall fw;
		if (fw.Initialize())
		{
			std::string path = GetApplicationExecutablePath();
			fw.AddApplication(path, "StreamDivert");
		}
		else
		{
			error("Failed to initialize FW object");
		}
	}
	
	info("Parsing config file...");
	RelayConfig cfg = LoadConfig(cfgPath);
	info("Parsed %d inbound and %d outbound relay entries.", cfg.inboundRelayEntries.size(), cfg.outboundRelayEntries.size());

	info("Starting packet diverters...");
	std::vector<BaseProxy*> proxies;
	std::map<UINT16, std::vector<InboundRelayEntry>> mappedInboundTCPRelayEntries;
	std::vector<InboundRelayEntry> inboundUDPRelayEntries;
	std::vector<InboundRelayEntry> inboundICMPRelayEntries;
	for (auto entry : cfg.inboundRelayEntries)
	{
		if (entry.protocol == "tcp")
		{
			std::vector<InboundRelayEntry>& entries = mappedInboundTCPRelayEntries[entry.localPort];
			entries.push_back(entry);
		}
		else if (entry.protocol == "udp")
		{
			inboundUDPRelayEntries.push_back(entry);
		}
		else if (entry.protocol == "icmp")
		{
			inboundICMPRelayEntries.push_back(entry);
		}
	}

	for (auto mapping : mappedInboundTCPRelayEntries)
	{
		InboundTCPDivertProxy* proxy = new InboundTCPDivertProxy(mapping.first, mapping.second);
		proxy->Start();
		proxies.push_back(proxy);
		proxy->Stop();
	}
	
	InboundUDPDivertProxy* inboundUDPProxy = new InboundUDPDivertProxy(inboundUDPRelayEntries);
	inboundUDPProxy->Start();
	proxies.push_back(inboundUDPProxy);

	InboundICMPDivertProxy* inboundICMPProxy = new InboundICMPDivertProxy(inboundICMPRelayEntries);
	inboundICMPProxy->Start();
	proxies.push_back(inboundICMPProxy);

	OutboundDivertProxy* outboundProxy = new OutboundDivertProxy(cfg.outboundRelayEntries);
	outboundProxy->Start();
	proxies.push_back(outboundProxy);

	//Wait indefinitely
	std::promise<void> p;
	p.get_future().wait();	
}


