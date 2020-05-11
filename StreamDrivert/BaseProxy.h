#pragma once
#include <windows.h>
#include <thread>
#include <mutex>
#include "windivert.h"
#include"ipaddr.h"

static IpAddr anyIpAddr = IpAddr("0.0.0.0");
static void cleanup(HANDLE ioport, OVERLAPPED *ignore);

struct EndpointKey
{
	in6_addr addr;
	UINT16 port;

	bool operator<(const EndpointKey& rhs) const { return memcmp(this, &rhs, sizeof(EndpointKey)) < 0; }
	bool operator==(const EndpointKey& rhs) const { return memcmp(this, &rhs, sizeof(EndpointKey)) == 0; }
};

struct Endpoint
{
	IpAddr addr;
	UINT16 port;
};

class BaseProxy
{
protected:
	bool running;
	HANDLE hDivert;
	HANDLE ioPort;
	HANDLE event;
	std::thread divertThread;
	INT16 priority;
	std::string filterStr;
	std::string selfDescStr;
	std::recursive_mutex resourceLock;

	std::string getIpAddrIpStr(IpAddr& addr);
	virtual std::string getStringDesc();
	virtual std::string generateDivertFilterString();
	virtual void DivertWorker();
	virtual void ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr) = 0;
	virtual void ProcessICMPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr& srcAddr, IpAddr& dstAddr) = 0;
	virtual void ProcessUDPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr& srcAddr, IpAddr& dstAddr) = 0;

public:
	BaseProxy();
	~BaseProxy();
	virtual bool Start();
	virtual bool Stop();
};

