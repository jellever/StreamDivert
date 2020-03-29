// StreamDrivert.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>
#include <future>
#include "StreamDrivert.h"
#include "DivertProxy.h"
#include "utils.h"


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
	char* config_file = argv[1];
	DWORD filesize = 0;
	DWORD outLength = 0;
	HANDLE hConfigFile = CreateFile(config_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hConfigFile == INVALID_HANDLE_VALUE)
	{
		exit(EXIT_FAILURE);
	}
	filesize = GetFileSize(hConfigFile, NULL);
	if (filesize == 0)
	{
		exit(EXIT_FAILURE);
	}

	char* config_file_data = new char[filesize+1];
	ZeroMemory(config_file_data, filesize + 1);
	BOOL suc = ReadFile(hConfigFile, config_file_data, filesize, &outLength, NULL);
	if (!suc)
	{
		exit(EXIT_FAILURE);
	}
	CloseHandle(hConfigFile);

	std::vector<DIVERT_PROXY_RECORD> hostProxies;
	DIVERT_PROXY_RECORD record;
	stringToIp("10.0.1.36", record.srcAddr);
	stringToIp("10.0.1.38", record.forwardAddr);
	record.forwardPort = 8080;

	hostProxies.push_back(record);
	DivertProxy proxy(8080, 34010, hostProxies);
	proxy.Start();	

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


