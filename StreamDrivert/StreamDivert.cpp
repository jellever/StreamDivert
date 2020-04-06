// StreamDrivert.cpp : Defines the entry point for the application.
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
#include "InboundDivertProxy.h"
#include "OutboundDivertProxy.h"
#include "utils.h"
#include "config.h"



// Global Variables:
HINSTANCE hInst;                                // current instance
/*
* Lock to sync output.
*/


int __cdecl main(int argc, char **argv)
{
	if (argc != 2)
	{
		exit(EXIT_FAILURE);
	}
	
	RelayConfig cfg = LoadConfig(argv[1]);
	std::vector<BaseProxy*> proxies;

	for (auto cfg_proxy : cfg.inboundProxies)
	{
		InboundDivertProxy* proxy = new InboundDivertProxy(cfg_proxy.first, cfg_proxy.second.relayEntries);
		proxy->Start();
		proxies.push_back(proxy);
	}

	OutboundDivertProxy* proxy = new OutboundDivertProxy(cfg.outboundProxy.relayEntries);
	proxy->Start();
	proxies.push_back(proxy);

	//Wait indefinitely
	std::promise<void> p;
	p.get_future().wait();	
}


