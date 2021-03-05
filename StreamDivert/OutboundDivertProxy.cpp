#include "stdafx.h"
#include "OutboundDivertProxy.h"
#include "utils.h"
#include <set>
#include <iphlpapi.h>
#include "interfaces.h"


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



PacketAction OutboundDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{	
	if (true)
	{
		if (addr->Outbound)
		{
			for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
			{
				if (record->protocol == "tcp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr) && tcp_hdr->DstPort == htons(record->dstPort))
				{
					UINT32 ifIfx = addr->Network.IfIdx;
					EndpointKey key;
					key.addr = srcAddr.get_addr();
					key.port = tcp_hdr->SrcPort;					
					if (record->interfaceIdx != -1)
					{
						IpAddr newSrc;
						bool ifAddrLookupSuc = GetInterfaceAddressByIdx(record->interfaceIdx, newSrc, srcAddr.get_family(), true);
						if (ifAddrLookupSuc)
						{
							this->logDebug("Modify packet src -> %s:%hu", newSrc.to_string().c_str(), tcp_hdr->SrcPort);
							key.addr = newSrc.get_addr();
							this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, newSrc);
							addr->Network.IfIdx = record->interfaceIdx;
							if (ip_hdr)
							{
								WINDIVERT_IPHDR_SET_DF(ip_hdr, 0);
							}
						}
						else if (record->forceInterfaceIdx)
						{
							return PacketAction::STATUS_DROP;
						}
					}
					this->logDebug("Modify packet dst -> %s:%hu", record->forwardAddr.to_string().c_str(), record->forwardPort);
					this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);
					tcp_hdr->DstPort = htons(record->forwardPort);
					this->incomingTCPMap[key] = { dstAddr, tcp_hdr->DstPort, ifIfx };
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
					EndpointKey key;
					key.addr = dstAddr.get_addr();
					key.port = tcp_hdr->DstPort;
					std::map<EndpointKey, Endpoint>::iterator it = this->incomingTCPMap.find(key);
					if (it != this->incomingTCPMap.end())
					{
						if (record->interfaceIdx != -1)
						{
							IpAddr newDst;
							bool ifAddrLookupSuc = GetInterfaceAddressByIdx(it->second.ifIfx, newDst, dstAddr.get_family(), true);
							if (ifAddrLookupSuc)
							{
								this->logDebug("Modify packet dst -> %s:%hu", newDst.to_string().c_str(), tcp_hdr->DstPort);
								this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, newDst);
								addr->Network.IfIdx = it->second.ifIfx;
								if (ip_hdr)
								{
									WINDIVERT_IPHDR_SET_DF(ip_hdr, 0);
								}
							}
							else if (record->forceInterfaceIdx)
							{
								return PacketAction::STATUS_DROP;
							}
						}
						IpAddr& lookupAddr = it->second.addr;
						this->logDebug("Modify packet src -> %s:%hu", lookupAddr.to_string().c_str(), ntohs(it->second.port));
						this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, lookupAddr);
						tcp_hdr->SrcPort = it->second.port;
						
						break;
					}									
				}
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
}


PacketAction OutboundDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (addr->Outbound)
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "icmp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr))
			{
				this->logDebug("Modify packet dst -> %s", record->forwardAddr.to_string().c_str());
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
						this->logDebug("Modify packet src -> %s", lookupAddr.to_string().c_str());
						break;
					}
				}
				else
				{
					this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, record->dstAddr);					
					this->logDebug("Modify packet src -> %s", record->dstAddr.to_string().c_str());
					break;
				}
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
}

PacketAction OutboundDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (addr->Outbound)
	{
		for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
		{
			if (record->protocol == "udp" && (dstAddr == record->dstAddr || record->dstAddr == anyIpAddr) && udp_header->DstPort == htons(record->dstPort))
			{
				this->logDebug("Modify packet dst -> %s:%hu", record->forwardAddr.to_string().c_str(), record->forwardPort);
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
						this->logDebug("Modify packet src -> %s:%hu", addr.to_string().c_str(), ntohs(it->second.port));
						break;
					}
				}
				else
				{
					this->OverrideIPHeaderSrc(ip_hdr, ip6_hdr, record->dstAddr);					
					udp_header->SrcPort = htons(record->dstPort);
					this->logDebug("Modify packet src -> %s:%hu", record->dstAddr.to_string().c_str(), record->dstPort);
					break;
				}
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
}

OutboundDivertProxy::OutboundDivertProxy(bool verbose, std::vector<OutboundRelayEntry>& relayEntries)
	: BaseProxy(verbose)
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
