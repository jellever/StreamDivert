#include "stdafx.h"
#include "InboundUDPDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>


InboundUDPDivertProxy::InboundUDPDivertProxy(bool verbose, const std::vector<InboundRelayEntry>& proxyRecords)
	: BaseProxy(verbose)
{
	this->proxyRecords = proxyRecords;
	this->selfDescStr = this->getStringDesc();
}

InboundUDPDivertProxy::~InboundUDPDivertProxy()
{
}

bool InboundUDPDivertProxy::Stop()
{
	this->connectionMap.clear();
	return BaseProxy::Stop();
}

std::string InboundUDPDivertProxy::getStringDesc()
{
	std::string result = std::string("InboundUDPDivertProxy()");
	return result;
}

PacketAction InboundUDPDivertProxy::ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

PacketAction InboundUDPDivertProxy::ProcessICMPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr& srcAddr, IpAddr& dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

PacketAction InboundUDPDivertProxy::ProcessUDPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr& srcAddr, IpAddr& dstAddr)
{
	if (!addr->Outbound)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			// Inbound packets from a configured source address
			if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr) &&
				udp_header->DstPort == htons(record->localPort))
			{
				std::string forwardAddrStr = record->forwardAddr.to_string();
				std::string dstAddrStr = dstAddr.to_string();
				this->logDebug("Modify packet src -> %s:%hu", dstAddrStr.c_str(), ntohs(udp_header->SrcPort));
				this->logDebug("Modify packet dst -> %s:%hu", forwardAddrStr.c_str(), record->forwardPort);

				EndpointKey key;
				key.addr = record->forwardAddr.get_addr();
				key.port = udp_header->SrcPort;
				this->connectionMap[key] = { srcAddr, udp_header->DstPort };

				this->SwapIPHeaderDstToSrc(ip_hdr, ip6_hdr);
				this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, record->forwardAddr);
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
					this->logDebug("Modify packet src -> %s:%hu", dstAddr.to_string().c_str(), ntohs(it->second.port));
					this->logDebug("Modify packet dst -> %s:%hu", lookupAddr.to_string().c_str(), ntohs(udp_header->DstPort));

					this->SwapIPHeaderDstToSrc(ip_hdr, ip6_hdr);
					this->OverrideIPHeaderDst(ip_hdr, ip6_hdr, lookupAddr);
					udp_header->SrcPort = it->second.port;
					addr->Outbound = 1;
					break;
				}
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
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

			recordFilterStr = "(udp.DstPort == " + std::to_string(record->localPort) + ")";
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
			recordFilterStr = "(udp.DstPort == " + std::to_string(record->localPort) + " and " + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
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
