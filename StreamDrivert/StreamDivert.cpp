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
#include "DivertProxy.h"
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
	std::map<UINT16, DivertProxy*> proxies;

	for (auto cfg_proxy : cfg.proxies)
	{
		DivertProxy* proxy = new DivertProxy(cfg_proxy.first, cfg_proxy.second.relayEntries);
		proxy->Start();		
		proxies[cfg_proxy.first] = proxy;
	}		
	

	//Wait indefinitely
	std::promise<void> p;
	p.get_future().wait();

	/*
	Config cfg;
	cfg.proxyPort = PROXY_PORT;
	cfg.divertRecords = parseCfgFile(config_file_data, filesize);	
	runProxy(&cfg);
	*/
}


