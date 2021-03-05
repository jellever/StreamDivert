#pragma once
#include <windows.h>
#include <thread>
#include <mutex>
#include "windivert.h"
#include"ipaddr.h"

static IpAddr anyIpAddr = IpAddr("0.0.0.0");
static IpAddr anyIp6Addr = IpAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
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
	UINT32 ifIfx;
};

enum PacketAction
{
	STATUS_UNKOWN,
	STATUS_PROCEED,
	STATUS_DROP
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
	bool verbose;

	void logDebug(const char* msg, ...);
	void logInfo(const char* msg, ...);
	void logWarning(const char* msg, ...);
	void logError(const char* msg, ...);
	std::string getIpAddrIpStr(IpAddr& addr);
	virtual std::string getStringDesc();
	virtual std::string generateDivertFilterString();
	void SwapIPHeaderSrcToDst(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr);
	void SwapIPHeaderDstToSrc(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr);
	void OverrideIPHeaderSrc(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, IpAddr& addr);
	void OverrideIPHeaderDst(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, IpAddr& addr);
	virtual void DivertWorker();
	virtual PacketAction ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr) = 0;
	virtual PacketAction ProcessICMPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr& srcAddr, IpAddr& dstAddr) = 0;
	virtual PacketAction ProcessUDPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr& srcAddr, IpAddr& dstAddr) = 0;

public:
	BaseProxy(bool verbose);
	~BaseProxy();
	virtual bool Start();
	virtual bool Stop();
};

