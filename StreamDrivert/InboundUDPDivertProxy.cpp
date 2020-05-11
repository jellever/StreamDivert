#include "stdafx.h"
#include "InboundUDPDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>


InboundUDPDivertProxy::InboundUDPDivertProxy(const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords)
{
	this->localPort = localPort;
	this->proxyRecords = proxyRecords;
	this->selfDescStr = this->getStringDesc();
}

InboundUDPDivertProxy::~InboundUDPDivertProxy()
{
}

bool InboundUDPDivertProxy::Start()
{
	//lock scope
	{
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		info("%s: Start", this->selfDescStr.c_str());		
		this->selfDescStr = this->getStringDesc();		

		BaseProxy::Start();
	}//lock scope
	
	return true;

failure:
	this->Stop();
	return false;
}

bool InboundUDPDivertProxy::Stop()
{
	info("%s: Stop", this->selfDescStr.c_str());
	{//lock scope
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		BaseProxy::Stop();
		
	}//lock scope
	
	return true;
}


std::string InboundUDPDivertProxy::getStringDesc()
{
	std::string result = std::string("InboundUDPDivertProxy(" + std::to_string(this->localPort) + ")");
	return result;
}

void InboundUDPDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
}

void InboundUDPDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
}

void InboundUDPDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (true)
	{
		if (!addr->Outbound)
		{
			for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
			{
				// Inbound packets from a configured source address
				if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr) &&
					udp_header->DstPort == htons(this->localPort))
				{
					std::string forwardAddrStr = record->forwardAddr.to_string();
					std::string dstAddrStr = dstAddr.to_string();
					info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), dstAddrStr.c_str(), ntohs(udp_header->SrcPort));
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), forwardAddrStr.c_str(), record->forwardPort);

					EndpointKey key;
					key.addr = record->forwardAddr.get_addr();
					key.port = udp_header->SrcPort;
					this->connectionMap[key] = { srcAddr, udp_header->DstPort };

					if (ip_hdr)
					{
						ip_hdr->SrcAddr = ip_hdr->DstAddr;
						ip_hdr->DstAddr = record->forwardAddr.get_ipv4_addr().S_un.S_addr;
					}
					else if (ip6_hdr)
					{
						*(in6_addr*)&ip6_hdr->SrcAddr[0] = *(in6_addr*)&ip6_hdr->DstAddr[0];
						*(in6_addr*)&ip6_hdr->DstAddr[0] = record->forwardAddr.get_addr();
					}
					udp_header->DstPort = htons(record->forwardPort);
					addr->Outbound = 1;
					break;
				}
				// Inbound packets from a forward address
				else if ((srcAddr == record->forwardAddr || record->srcAddr == anyIpAddr) &&
					udp_header->SrcPort == htons(record->forwardPort))
				{
					EndpointKey key;
					key.addr = srcAddr.get_addr();
					key.port = udp_header->DstPort;
					std::map<EndpointKey, Endpoint>::iterator it = this->connectionMap.find(key);
					if (it != this->connectionMap.end())
					{
						IpAddr& lookupAddr = it->second.addr;
						info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), dstAddr.to_string().c_str(), ntohs(it->second.port));
						info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), lookupAddr.to_string().c_str(), ntohs(udp_header->DstPort));
						if (ip_hdr)
						{
							ip_hdr->SrcAddr = ip_hdr->DstAddr;
							ip_hdr->DstAddr = lookupAddr.get_ipv4_addr().S_un.S_addr;
						}
						else if (ip6_hdr)
						{
							*(in6_addr*)&ip6_hdr->SrcAddr = *(in6_addr*)&ip6_hdr->DstAddr;
							*(in6_addr*)&ip6_hdr->DstAddr = lookupAddr.get_addr();
						}
						udp_header->SrcPort = it->second.port;
						addr->Outbound = 1;
						break;
					}
				}
			}
		}		
	}
}

std::string InboundUDPDivertProxy::generateDivertFilterString()
{
	std::string result = "udp";
	std::set<std::string> orExpressions;	

	//check for wildcard address
	bool containsWildcard = false;
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == anyIpAddr)
		{
			std::string forwardAddrIpStr = this->getIpAddrIpStr(record->forwardAddr);
			std::string recordFilterStr;
			
			recordFilterStr = "(udp.DstPort == " + std::to_string(this->localPort) + ")";
			orExpressions.insert(recordFilterStr);						
			containsWildcard = true;			
		}
	}
	
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		std::string srcAddrIpStr = this->getIpAddrIpStr(record->srcAddr);
		std::string forwardAddrIpStr = this->getIpAddrIpStr(record->forwardAddr);			
		std::string recordFilterStr;

		if (!containsWildcard)
		{
			recordFilterStr = "(udp.DstPort == " + std::to_string(this->localPort) + " and " + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
			orExpressions.insert(recordFilterStr);
		}
		recordFilterStr = "(udp.SrcPort == " + std::to_string(record->forwardPort) + " and " + forwardAddrIpStr + ".SrcAddr == " + record->forwardAddr.to_string() + ")";
		orExpressions.insert(recordFilterStr);
	}
	

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}
