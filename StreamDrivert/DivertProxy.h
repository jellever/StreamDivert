#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include "config.h"

static void cleanup(HANDLE ioport, OVERLAPPED *ignore);


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

#define MAXPACKETSIZE			0xFFFF

class DivertProxy
{
private:
	bool running;
	HANDLE hDivert;
	HANDLE ioPort;
	HANDLE event;
	SOCKET proxySock;
	std::thread divertThread;
	std::thread proxyThread;
	INT16 priority;
	std::mutex resourceLock;

	UINT16 localPort;
	UINT16 localProxyPort;
	std::vector<RelayEntry> proxyRecords;
	std::string filterStr;

	std::string getFiendlyProxyRecordsStr();
	std::string getStringDesc();
	void DivertWorker();
	void ProxyWorker();
	void ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData);
	void ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData);
	std::string generateDivertFilterString();
	bool findProxyRecordBySrcAddr(IpAddr& srcIp, RelayEntry& proxyRecord);
public:
	DivertProxy(const UINT16 localPort, const std::vector<RelayEntry>& proxyRecords);
	~DivertProxy();
	bool Start();
	bool Stop();
};
