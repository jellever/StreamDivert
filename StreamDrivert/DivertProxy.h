#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>

static void cleanup(HANDLE ioport, OVERLAPPED *ignore);


struct DIVERT_PROXY_RECORD
{
	UINT32 srcAddr;
	UINT32 forwardAddr;
	UINT16 forwardPort;
};

struct ProxyConnectionWorkerData
{
	SOCKET clientSock;
	sockaddr_in clientAddr;
};

struct ProxyTunnelWorkerData
{
	SOCKET sockA;
	UINT32 sockAAddr;
	UINT16 sockAPort;
	SOCKET sockB;
	UINT32 sockBAddr;
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
	std::vector<DIVERT_PROXY_RECORD> proxyRecords;
	std::string filterStr;

	std::string getFiendlyProxyRecordsStr();
	std::string getStringDesc();
	void DivertWorker();
	void ProxyWorker();
	void ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData);
	void ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData);
	std::string generateDivertFilterString();
	bool findProxyRecordBySrcAddr(UINT32 srcIp, DIVERT_PROXY_RECORD& proxyRecord);
public:
	DivertProxy(UINT16 localPort, UINT16 proxyPort, std::vector<DIVERT_PROXY_RECORD> proxyRecords);
	~DivertProxy();
	bool Start();
	bool Stop();
};
