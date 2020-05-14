#include "stdafx.h"
#include "OutboundDivertProxy.h"
#include "utils.h"
#include <set>


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
		if (record->protocol == "tcp" || record->protocol == "icmp" || record->protocol == "udp")
		{
			if (record->protocol == "icmp")
			{
				protocols.insert("icmpv6");
			}			
			protocols.insert(record->protocol);
		}
		if (record->protocol == "tcp" || record->protocol == "udp")
		{
			if (record->dstAddr == anyIpAddr)
			{
				recordFilterStr = "(" + record->protocol + ".DstPort == " + std::to_string(record->dstPort) + ")";
				orExpressions.push_back(recordFilterStr);
				recordFilterStr = "(" + record->protocol + ".SrcPort == " + std::to_string(record->dstPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
			else
			{
				std::string dstAddrIpStr = this->getIpAddrIpStr(record->dstAddr);
				std::string forwardAddrIpStr = this->getIpAddrIpStr(record->forwardAddr);

				recordFilterStr = "(" + dstAddrIpStr + ".DstAddr == " + record->dstAddr.to_string() + " and " + record->protocol + ".DstPort == " + std::to_string(record->dstPort) + ")";
				orExpressions.push_back(recordFilterStr);

				recordFilterStr = "(" + forwardAddrIpStr + ".SrcAddr == " + record->forwardAddr.to_string() + " and " + record->protocol + ".SrcPort == " + std::to_string(record->forwardPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
		}
	}
	result = "(";
	joinStr(protocols, std::string(" or "), result);
	result += ")";

	if (orExpressions.size() > 0)
	{
		result += " and (";
		joinStr(orExpressions, std::string(" or "), result);
		result += ")";
	}
	return result;
}

void OutboundDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (true)
	{
		if (addr->Outbound)
		{
			for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
			{
				if (record->protocol == "tcp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr) && tcp_hdr->DstPort == htons(record->dstPort))
				{							
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), record->forwardAddr.to_string().c_str(), record->forwardPort);
					if (record->dstAddr == anyIpAddr)
					{
						EndpointKey key;
						key.addr = srcAddr.get_addr();
						key.port = tcp_hdr->SrcPort;
						this->incomingTCPMap[key] = { dstAddr, tcp_hdr->DstPort };
					}
					this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);
					tcp_hdr->DstPort = htons(record->forwardPort);
					break;
				}
			}
		}
		else
		{
			for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
			{
				if (record->protocol == "tcp" && (srcAddr == record->forwardAddr || record->dstAddr == anyIpAddr) && tcp_hdr->SrcPort == htons(record->forwardPort))
				{					
					if (record->dstAddr == anyIpAddr)
					{
						EndpointKey key;
						key.addr = dstAddr.get_addr();
						key.port = tcp_hdr->DstPort;
						std::map<EndpointKey, Endpoint>::iterator it = this->incomingTCPMap.find(key);
						if (it != this->incomingTCPMap.end())
						{
							IpAddr& lookupAddr = it->second.addr;							
							this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, lookupAddr);
							tcp_hdr->SrcPort = it->second.port;
							info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), lookupAddr.to_string().c_str(), ntohs(it->second.port));
							break;
						}						
					}
					else
					{
						this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, record->dstAddr);						
						tcp_hdr->SrcPort = htons(record->dstPort);
						info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), record->dstAddr.to_string().c_str(), record->dstPort);
						break;
					}					
				}
			}
		}
	}
}


void OutboundDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (addr->Outbound)
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "icmp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr))
			{
				info("%s: Modify packet dst -> %s", this->selfDescStr.c_str(), record->forwardAddr.to_string().c_str());
				if (record->dstAddr == anyIpAddr)
				{
					EndpointKey key;
					key.addr = srcAddr.get_addr();
					key.port = 0;
					this->incomingICMPMap[key] = { dstAddr, 0};
				}
				this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);				
				break;
			}
		}
	}
	else
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "icmp" && (srcAddr == record->forwardAddr || record->dstAddr == anyIpAddr))
			{
				if (record->dstAddr == anyIpAddr)
				{
					EndpointKey key;
					key.addr = dstAddr.get_addr();
					key.port = 0;
					std::map<EndpointKey, Endpoint>::iterator it = this->incomingICMPMap.find(key);
					if (it != this->incomingICMPMap.end())
					{
						IpAddr& lookupAddr = it->second.addr;
						this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, lookupAddr);						
						info("%s: Modify packet src -> %s", this->selfDescStr.c_str(), lookupAddr.to_string().c_str());
						break;
					}
				}
				else
				{
					this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, record->dstAddr);					
					info("%s: Modify packet src -> %s", this->selfDescStr.c_str(), record->dstAddr.to_string().c_str());
					break;
				}
			}
		}
	}
}

void OutboundDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (addr->Outbound)
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "udp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr) && udp_header->DstPort == htons(record->dstPort))
			{
				info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), record->forwardAddr.to_string().c_str(), record->forwardPort);
				if (record->dstAddr == anyIpAddr)
				{
					EndpointKey key;
					key.addr = srcAddr.get_addr();
					key.port = udp_header->SrcPort;
					this->incomingUDPMap[key] = { dstAddr, udp_header->DstPort };
				}
				this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);
				udp_header->DstPort = htons(record->forwardPort);
				break;
			}
		}
	}
	else
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "udp" && (srcAddr == record->forwardAddr || record->dstAddr == anyIpAddr) && udp_header->SrcPort == htons(record->forwardPort))
			{
				if (record->dstAddr == anyIpAddr)
				{
					EndpointKey key;
					key.addr = dstAddr.get_addr();
					key.port = udp_header->DstPort;
					std::map<EndpointKey, Endpoint>::iterator it = this->incomingUDPMap.find(key);
					if (it != this->incomingUDPMap.end())
					{
						IpAddr& addr = it->second.addr;
						this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, addr);						
						udp_header->SrcPort = it->second.port;
						info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), addr.to_string().c_str(), ntohs(it->second.port));
						break;
					}
				}
				else
				{
					this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, record->dstAddr);					
					udp_header->SrcPort = htons(record->dstPort);
					info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), record->dstAddr.to_string().c_str(), record->dstPort);
					break;
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
	this->incomingTCPMap.clear();
	this->incomingUDPMap.clear();
	this->incomingICMPMap.clear();
	return BaseProxy::Stop();
}
