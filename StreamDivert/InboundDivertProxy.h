#pragma once
#include <winsock2.h>
#include <windows.h>
#include"ipaddr.h"


struct ProxyConnectionWorkerData
{
	SOCKET clientSock;
	sockaddr_in6 clientAddr;
};

struct ProxyTunnelWorkerData
{
	SOCKET sockA;
	IpAddr sockAAddr;
	UINT16 sockAPort;
	SOCKET sockB;
	IpAddr sockBAddr;
	UINT16 sockBPort;
};
