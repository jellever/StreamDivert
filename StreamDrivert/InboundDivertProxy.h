#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include "windivert.h"
#include "BaseProxy.h"
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


class InboundDivertProxy : public BaseProxy
{
protected:
	SOCKET proxySock;
	std::thread proxyThread;

	UINT16 localPort;
	UINT16 localProxyPort;
	std::vector<InboundRelayEntry> proxyRecords;

	std::string getFiendlyProxyRecordsStr();
	std::string getStringDesc();
	void ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, UINT8 protocol, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr);
	void ProxyWorker();
	void ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData);
	void ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData);
	std::string generateDivertFilterString();
	bool findProxyRecordBySrcAddr(IpAddr& srcIp, InboundRelayEntry& proxyRecord);
public:
	InboundDivertProxy(const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords);
	~InboundDivertProxy();
	bool Start();
	bool Stop();
};
