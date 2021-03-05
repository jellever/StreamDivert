#include "stdafx.h"
#include "InboundICMPDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>

InboundICMPDivertProxy::InboundICMPDivertProxy(bool verbose, const std::vector<InboundRelayEntry>& proxyRecords)
	: BaseProxy(verbose)
{
	this->proxyRecords = proxyRecords;
	this->selfDescStr = this->getStringDesc();
}


InboundICMPDivertProxy::~InboundICMPDivertProxy()
{
}

bool InboundICMPDivertProxy::Stop()
{
	this->connectionMap.clear();
	return BaseProxy::Stop();
}


std::string InboundICMPDivertProxy::getStringDesc()
{
	return std::string("InboundICMPDivertProxy()");
}

PacketAction InboundICMPDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

PacketAction InboundICMPDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (!addr->Outbound)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			// Inbound packets from a configured source address
			if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr))
			{
				std::string forwardAddrStr = record->forwardAddr.to_string();
				std::string dstAddrStr = dstAddr.to_string();
				this->logDebug("Modify packet src -> %s",  dstAddrStr.c_str());
				this->logDebug("Modify packet dst -> %s", forwardAddrStr.c_str());

				EndpointKey key;
				key.addr = record->forwardAddr.get_addr();
				key.port = 0;
				this->connectionMap[key] = { srcAddr, 0 };

				this->SwapIPHeaderDstToSrc(ip_hdr, ip6_hdr);
				this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);
				addr->Outbound = 1;				
				break;
			}
			// Inbound packets from a forward address
			else if ((srcAddr == record->forwardAddr || record->srcAddr == anyIpAddr))
			{
				EndpointKey key;
				key.addr = srcAddr.get_addr();
				key.port = 0;
				std::map<EndpointKey, Endpoint>::iterator it = this->connectionMap.find(key);
				if (it != this->connectionMap.end())
				{
					IpAddr& lookupAddr = it->second.addr;
					this->logDebug("Modify packet src -> %s", dstAddr.to_string().c_str());
					this->logDebug("Modify packet dst -> %s", lookupAddr.to_string().c_str());

					this->SwapIPHeaderDstToSrc(ip_hdr, ip6_hdr);
					this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, lookupAddr);
					addr->Outbound = 1;					
					break;
				}
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
}

PacketAction InboundICMPDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

std::string InboundICMPDivertProxy::generateDivertFilterString()
{
	std::string result = "(icmp or icmpv6)";
	std::set<std::string> orExpressions;

	if (this->proxyRecords.size() == 0)
	{
		return "false";
	}

	//check for wildcard address
	bool containsWildcard = false;
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == anyIpAddr)
		{
			containsWildcard = true;
		}
	}

	if (!containsWildcard)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			std::string srcAddrIpStr = this->getIpAddrIpStr(record->srcAddr);
			std::string forwardAddrIpStr = this->getIpAddrIpStr(record->forwardAddr);
			std::string recordFilterStr;
			
			recordFilterStr = "(" + forwardAddrIpStr + ".SrcAddr == " + record->forwardAddr.to_string() + ")";
			orExpressions.insert(recordFilterStr);

			recordFilterStr = "(" + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
			orExpressions.insert(recordFilterStr);
		}
	}

	if (orExpressions.size() > 0)
	{
		result += " and (";
		joinStr(orExpressions, std::string(" or "), result);
		result += ")";
	}
	return result;
}
