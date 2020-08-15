#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include "windivert.h"
#include "BaseProxy.h"
#include "config.h"
#include"ipaddr.h"
#include "InboundDivertProxy.h"


class InboundTCPDivertProxy : public BaseProxy
{
protected:
	SOCKET proxySock;
	std::thread proxyThread;

	UINT16 localPort;
	UINT16 localProxyPort;
	std::vector<InboundRelayEntry> proxyRecords;

	std::string getStringDesc();
	void ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr);
	void ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr);
	void ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr);
	void ProxyWorker();
	void ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData);
	std::string generateDivertFilterString();
	bool findProxyRecordBySrcAddr(IpAddr& srcIp, InboundRelayEntry& proxyRecord);
public:
	InboundTCPDivertProxy(const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords);
	~InboundTCPDivertProxy();
	bool Start();
	bool Stop();
};
