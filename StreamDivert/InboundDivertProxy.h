#pragma once
#include <winsock2.h>
#include <windows.h>
#include"ipaddr.h"


struct ProxyConnectionWorkerData
{
	SOCKET clientSock;
	sockaddr_in6 clientAddr;
};

