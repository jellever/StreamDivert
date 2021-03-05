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
#include "interfaces.h"
#include "utils.h"

// Global Variables:
HINSTANCE hInst;                                // current instance
const char* version = "1.1.0";


int __cdecl main(int argc, char **argv)
{
	bool modifyFW = false;
	bool verbose = false;
	if (argc < 2)
	{
		char* filename = basename(argv[0]);
		fprintf(stderr, "StreamDivert %s - Redirect network traffic\n", version);
		fprintf(stderr, "%s cfg_file [-v] [-f]\n", filename);
		fprintf(stderr, "%s interfaces\n", filename);
		fprintf(stderr, "-f\tModify windows firewall to allow redirecting incomming TCP streams\n");
		fprintf(stderr, "-v\tPrint modified packets to stderr\n");
		fprintf(stderr, "interfaces\tPrint information regarding the network interfaces\n");

		exit(EXIT_SUCCESS);
	}
	if (argc == 2 && std::string(argv[1]) == "interfaces")
	{
		PrintInterfaceInfo();
		exit(EXIT_SUCCESS);
	}
	
	for (int i = 2; i < argc; i++)
	{
		std::string argval = argv[i];
		if (argval == "-f")
		{
			modifyFW = true;
		}
		else if (argval == "-v")
		{
			verbose = true;
		}
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
	RelayConfig cfg;
	bool cfgLoadResult = LoadConfig(cfgPath, cfg);
	if (!cfgLoadResult)
	{
		error("Failed to load config file!");
		exit(EXIT_FAILURE);
	}
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
		InboundTCPDivertProxy* proxy = new InboundTCPDivertProxy(verbose, mapping.first, mapping.second);
		proxy->Start();
		proxies.push_back(proxy);
		//proxy->Stop();
	}
	
	InboundUDPDivertProxy* inboundUDPProxy = new InboundUDPDivertProxy(verbose, inboundUDPRelayEntries);
	inboundUDPProxy->Start();
	proxies.push_back(inboundUDPProxy);

	InboundICMPDivertProxy* inboundICMPProxy = new InboundICMPDivertProxy(verbose, inboundICMPRelayEntries);
	inboundICMPProxy->Start();
	proxies.push_back(inboundICMPProxy);

	OutboundDivertProxy* outboundProxy = new OutboundDivertProxy(verbose, cfg.outboundRelayEntries);
	outboundProxy->Start();
	proxies.push_back(outboundProxy);

	//Wait indefinitely
	std::promise<void> p;
	p.get_future().wait();	
}
