#include "stdafx.h"
#include "OutboundDivertProxy.h"
#include "utils.h"


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
	std::string result = "tcp";
	std::vector<std::string> orExpressions;	
	std::string recordFilterStr;	

	for (auto record = this->relayEntries.begin(); record != this->relayEntries.end(); ++record)
	{
		if (record->dstAddr == anyIpAddr)
		{
			recordFilterStr = "(tcp.DstPort == " + std::to_string(record->dstPort) + ")";
			orExpressions.push_back(recordFilterStr);
			recordFilterStr = "(tcp.SrcPort == " + std::to_string(record->dstPort) + ")";
			orExpressions.push_back(recordFilterStr);			
		}
		else
		{
			recordFilterStr = "(ip.DstAddr == " + record->dstAddr.to_string() + " and tcp.DstPort == " + std::to_string(record->dstPort) + ")";
			orExpressions.push_back(recordFilterStr);
			recordFilterStr = "(ip.SrcAddr == " + record->forwardAddr.to_string() + " and tcp.SrcPort == " + std::to_string(record->forwardPort) + ")";
			orExpressions.push_back(recordFilterStr);
		}
	}
	
	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

void OutboundDivertProxy::ProcessTCPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, UINT8 protocol, PWINDIVERT_TCPHDR tcp_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	if (ip_hdr)
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
					ip_hdr->DstAddr = record->forwardAddr.get_ipv4_addr().S_un.S_addr;
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
							ip_hdr->SrcAddr = addr.get_ipv4_addr().S_un.S_addr;
							tcp_hdr->SrcPort = it->second.port;
							info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), addr.to_string().c_str(), ntohs(it->second.port));
						}						
					}
					else
					{
						ip_hdr->SrcAddr = record->dstAddr.get_ipv4_addr().S_un.S_addr;
						tcp_hdr->SrcPort = htons(record->dstPort);
						info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), record->dstAddr.to_string().c_str(), record->dstPort);
					}					
				}
			}
		}
	}
}

bool OutboundDivertProxy::findProxyRecordByDstAddr(IpAddr & dstAddr, OutboundRelayEntry & proxyRecord)
{
	return false;
}

OutboundDivertProxy::OutboundDivertProxy(std::vector<OutboundRelayEntry>& relayEntries)
{
	this->relayEntries = relayEntries;
	this->selfDescStr = this->getStringDesc();
}


OutboundDivertProxy::~OutboundDivertProxy()
{
}
