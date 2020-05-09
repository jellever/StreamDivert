#pragma once
#include <vector>
#include "BaseProxy.h"
#include "windivert.h"
#include "config.h"

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

class OutboundDivertProxy : public BaseProxy
{
protected:
	std::vector<OutboundRelayEntry> relayEntries;
	std::map<EndpointKey, Endpoint> incomingMap;

	std::string getFiendlyProxyRecordsStr();
	std::string getStringDesc();
	std::string generateDivertFilterString();
	void ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr);
	void ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr);
	void ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr);

public:
	OutboundDivertProxy(std::vector<OutboundRelayEntry>& relayEntries);
	~OutboundDivertProxy();
	virtual bool Stop();

};

