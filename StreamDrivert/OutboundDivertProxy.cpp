#include "stdafx.h"
#include "OutboundDivertProxy.h"
#include "utils.h"
#include <set>


std::string OutboundDivertProxy::getFiendlyProxyRecordsStr()
{
	std::string result;
	for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
	{
		std::string dstAddr = record->dstAddr.to_string();
		std::string forwardAddr = record->forwardAddr.to_string();
		result += dstAddr + ":" + std::to_string(record->dstPort) + " -> " + forwardAddr + ":" + std::to_string(record->forwardPort) + "\n";
	}
	return result;
}

std::string OutboundDivertProxy::getStringDesc()
{
	return std::string("OutboundDivertProxy()");
}

std::string OutboundDivertProxy::generateDivertFilterString()
{
	std::string result = "";
	std::set<std::string> protocols;
	std::vector<std::string> orExpressions;	
	std::string recordFilterStr;	

	for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
	{
		//TODO: Does this also capture icmpv6??
		if (record->protocol == "tcp" || record->protocol == "icmp" || record->protocol == "udp")
		{
			protocols.insert(record->protocol);
		}
		if (record->dstAddr == anyIpAddr)
		{
			recordFilterStr = "(tcp.DstPort == " + std::to_string(record->dstPort) + ")";
			orExpressions.push_back(recordFilterStr);
			recordFilterStr = "(tcp.SrcPort == " + std::to_string(record->dstPort) + ")";
			orExpressions.push_back(recordFilterStr);			
		}
		else
		{
			if (record->dstAddr.get_family() == IPFamily::IPv4)
			{
				recordFilterStr = "(ip.DstAddr == " + record->dstAddr.to_string() + " and tcp.DstPort == " + std::to_string(record->dstPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
			else if (record->dstAddr.get_family() == IPFamily::IPv6)
			{
				recordFilterStr = "(ipv6.DstAddr == " + record->dstAddr.to_string() + " and tcp.DstPort == " + std::to_string(record->dstPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}

			if (record->forwardAddr.get_family() == IPFamily::IPv4)
			{
				recordFilterStr = "(ipv6.SrcAddr == " + record->forwardAddr.to_string() + " and tcp.SrcPort == " + std::to_string(record->forwardPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
			else if (record->forwardAddr.get_family() == IPFamily::IPv6)
			{
				recordFilterStr = "(ipv6.SrcAddr == " + record->forwardAddr.to_string() + " and tcp.SrcPort == " + std::to_string(record->forwardPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}			
		}
	}
	result = "(";
	joinStr(protocols, std::string(" or "), result);
	result += ")";

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

void OutboundDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (true)
	{
		if (addr->Outbound == 1)
		{
			for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
			{
				if ((dstAddr == record->dstAddr || record->dstAddr == anyIpAddr) &&
					tcp_hdr->DstPort == htons(record->dstPort))
				{							
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), record->forwardAddr.to_string().c_str(), record->forwardPort);
					if (record->dstAddr == anyIpAddr)
					{
						EndpointKey key;
						key.addr = srcAddr.get_addr();
						key.port = tcp_hdr->SrcPort;
						this->incomingMap[key] = { dstAddr, tcp_hdr->DstPort };						
					}
					if (ip_hdr)
					{
						ip_hdr->DstAddr = record->forwardAddr.get_ipv4_addr().S_un.S_addr;
					}
					else if (ip6_hdr)
					{
						*(in6_addr*)&ip6_hdr->DstAddr[0] = record->forwardAddr.get_addr();
					}
					tcp_hdr->DstPort = htons(record->forwardPort);
				}
			}
		}
		else
		{
			for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
			{
				if ((srcAddr == record->forwardAddr || record->dstAddr == anyIpAddr) &&
					tcp_hdr->SrcPort == htons(record->forwardPort))
				{					
					if (record->dstAddr == anyIpAddr)
					{
						EndpointKey key;
						key.addr = dstAddr.get_addr();
						key.port = tcp_hdr->DstPort;
						std::map<EndpointKey, Endpoint>::iterator it = this->incomingMap.find(key);
						if (it != this->incomingMap.end())
						{
							IpAddr& addr = it->second.addr;							
							if (ip_hdr)
							{
								ip_hdr->SrcAddr = addr.get_ipv4_addr().S_un.S_addr;
							}
							else if (ip6_hdr)
							{
								*(in6_addr*)&ip6_hdr->SrcAddr[0] = addr.get_addr();
							}
							tcp_hdr->SrcPort = it->second.port;
							info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), addr.to_string().c_str(), ntohs(it->second.port));
						}						
					}
					else
					{
						if (ip_hdr)
						{
							ip_hdr->SrcAddr = record->dstAddr.get_ipv4_addr().S_un.S_addr;
						}
						else if (ip6_hdr)
						{
							*(in6_addr*)&ip6_hdr->SrcAddr[0] = record->dstAddr.get_addr();
						}
						tcp_hdr->SrcPort = htons(record->dstPort);
						info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), record->dstAddr.to_string().c_str(), record->dstPort);
					}					
				}
			}
		}
	}
}

OutboundDivertProxy::OutboundDivertProxy(std::vector<OutboundRelayEntry>& relayEntries)
{
	this->relayEntries = relayEntries;
	this->selfDescStr = this->getStringDesc();
}


OutboundDivertProxy::~OutboundDivertProxy()
{
}

bool OutboundDivertProxy::Stop()
{
	this->incomingMap.clear();
	return BaseProxy::Stop();
}

void OutboundDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
}

void OutboundDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
}
