#pragma once
#include "ipaddr.h"


int recvall(SOCKET sock, char* buffer, int len);
bool recvallb(SOCKET sock, char* buffer, int len);

int sendall(SOCKET sock, const char* buffer, int len);
bool sendallb(SOCKET sock, const char* buffer, int len);

bool recvstr(SOCKET sock, char* buf, int* len);


struct ProxyTunnelWorkerData
{
	SOCKET sockA;
	IpAddr sockAAddr;
	UINT16 sockAPort;
	SOCKET sockB;
	IpAddr sockBAddr;
	UINT16 sockBPort;
};

void ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData, std::string& logDesc);