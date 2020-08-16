#include "stdafx.h"
#include "InboundTCPDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>
#include "sockutils.h"


InboundTCPDivertProxy::InboundTCPDivertProxy(const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords)
	: socksServer(0)
{	
	this->localPort = localPort;
	this->localProxyPort = 0;
	this->proxyRecords = proxyRecords;
	this->proxySock = NULL;
	this->selfDescStr = this->getStringDesc();
	this->containsSocksRecords = false;
}

InboundTCPDivertProxy::~InboundTCPDivertProxy()
{
}

bool InboundTCPDivertProxy::Start()
{
	WSADATA wsa_data;
	WORD wsa_version = MAKEWORD(2, 2);
	int on = 1;
	int off = 0;
	struct sockaddr_in6 addr;

	//lock scope
	{
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		info("%s: Start", this->selfDescStr.c_str());

		if (WSAStartup(wsa_version, &wsa_data) != 0)
		{
			error("%s: failed to start WSA (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}
		this->proxySock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (this->proxySock == INVALID_SOCKET)
		{
			error("%s: failed to create socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int)) == SOCKET_ERROR)
		{
			error("%s: failed to re-use address (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
		{
			error("%s: failed to set socket dual-stack (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(0);
		addr.sin6_addr = in6addr_any;
		//inet_pton(AF_INET6, "::1", &addr.sin6_addr);
		if (::bind(this->proxySock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			error("%s: failed to bind socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
			goto failure;
		}

		struct sockaddr_in6 bind_addr;
		int bind_addr_len = sizeof(bind_addr);
		if (getsockname(this->proxySock, (struct sockaddr *)&bind_addr, &bind_addr_len) == -1)
		{
			error("%s: failed to get bind socket port (%d)", this->selfDescStr.c_str(), WSAGetLastError());
		}
		this->localProxyPort = ntohs(bind_addr.sin6_port);
		this->selfDescStr = this->getStringDesc();

		if (listen(this->proxySock, 16) == SOCKET_ERROR)
		{
			error("%s: failed to listen socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
			goto failure;
		}

		for each (auto record in this->proxyRecords)
		{
			if (record.type == InboundRelayEntryType::Socks)
			{
				this->socksServer.Start();
				containsSocksRecords = true;
				break;
			}
		}

		BaseProxy::Start();
	}//lock scope

	this->proxyThread = std::thread(&InboundTCPDivertProxy::ProxyWorker, this);
	return true;

failure:
	this->Stop();
	return false;
}


std::string InboundTCPDivertProxy::getStringDesc()
{
	std::string result = std::string("InboundTCPDivertProxy(" + std::to_string(this->localPort) + ":");
	if (this->localProxyPort == 0)
	{
		result += "?";
	}
	else
	{
		result += std::to_string(this->localProxyPort);
	}
	result += ")";
	return result;
}

void InboundTCPDivertProxy::ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr)
{
	if (!addr->Outbound)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr) &&
				tcp_hdr->DstPort == htons(this->localPort))
			{
				std::string dstAddrStr = dstAddr.to_string();
				if (record->type == InboundRelayEntryType::Divert)
				{
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), dstAddrStr.c_str(), this->localProxyPort);
					tcp_hdr->DstPort = htons(this->localProxyPort);
					break;
				}
				else if (record->type == InboundRelayEntryType::Socks)
				{
					int socksPort = this->socksServer.GetPort();
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), dstAddrStr.c_str(), socksPort);
					tcp_hdr->DstPort = htons(socksPort);
					break;
				}
			}
		}
	}
	else
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			if ((dstAddr == record->srcAddr || record->srcAddr == anyIpAddr))
			{
				if (
					(record->type == InboundRelayEntryType::Divert && tcp_hdr->SrcPort == htons(this->localProxyPort) ) ||
					(record->type == InboundRelayEntryType::Socks && tcp_hdr->SrcPort == htons(this->socksServer.GetPort()))
					)
				{
					std::string srcAddrStr = srcAddr.to_string();
					info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), srcAddrStr.c_str(), this->localPort);
					tcp_hdr->SrcPort = htons(this->localPort);
					break;
				}				
			}
		}
	}
}

void InboundTCPDivertProxy::ProxyWorker()
{	
	while (true)
	{
		struct sockaddr_in6  clientSockAddr;
		int size = sizeof(clientSockAddr);
		SOCKET incommingSock = accept(this->proxySock, (SOCKADDR *)&clientSockAddr, &size);
		if (incommingSock == INVALID_SOCKET)
		{
			std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
			if (this->running == false)
			{
				goto cleanup;
			}
			warning("%s: failed to accept socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
			continue;
		}
		IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
		std::string srcAddr = clientSockIp.to_string();
		info("%s: Incoming connection from %s:%hu", this->selfDescStr.c_str(), srcAddr.c_str(), ntohs(clientSockAddr.sin6_port));
		ProxyConnectionWorkerData* proxyConnectionWorkerData = new ProxyConnectionWorkerData();
		proxyConnectionWorkerData->clientSock = incommingSock;
		proxyConnectionWorkerData->clientAddr = clientSockAddr;
		std::thread proxyConnectionThread(&InboundTCPDivertProxy::ProxyConnectionWorker, this, proxyConnectionWorkerData);
		proxyConnectionThread.detach();
	}
cleanup:
	if (this->proxySock != NULL)
	{
		closesocket(this->proxySock);
		this->proxySock = NULL;
	}
	info("%s: ProxyWorker exiting", this->selfDescStr.c_str());
}

void InboundTCPDivertProxy::ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData)
{
	int off = 0;
	SOCKET destSock = NULL;
	SOCKET clientSock = proxyConnectionWorkerData->clientSock;
	sockaddr_in6 clientSockAddr = proxyConnectionWorkerData->clientAddr;
	IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
	delete proxyConnectionWorkerData;

	std::string selfDesc = this->getStringDesc();

	InboundRelayEntry proxyRecord;
	UINT16 clientSrcPort = ntohs(clientSockAddr.sin6_port);
	std::string srcAddr = clientSockIp.to_string();
	bool lookupSuccess = this->findProxyRecordBySrcAddr(clientSockIp, proxyRecord);
	if (lookupSuccess)
	{
		struct sockaddr_in6 destAddr;
		ZeroMemory(&destAddr, sizeof(destAddr));
		destAddr.sin6_family = AF_INET6;
		destAddr.sin6_addr = proxyRecord.forwardAddr.get_addr();
		destAddr.sin6_port = htons(proxyRecord.forwardPort);
		destSock = socket(AF_INET6, SOCK_STREAM, 0);
		if (destSock == INVALID_SOCKET)
		{
			error("%s: failed to create socket (%d)", selfDesc.c_str(), WSAGetLastError());
			goto cleanup;
		}
		if (setsockopt(destSock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
		{
			error("%s: failed to set connect socket dual-stack (%d)", selfDesc.c_str(), GetLastError());
			goto cleanup;
		}
		std::string forwardAddr = proxyRecord.forwardAddr.to_string();
		info("%s: Connecting to forward host %s:%hu", selfDesc.c_str(), forwardAddr.c_str(), proxyRecord.forwardPort);
		if (connect(destSock, (SOCKADDR *)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
		{
			error("%s: failed to connect socket (%d)", selfDesc.c_str(), WSAGetLastError());
			goto cleanup;
		}

		info("%s: Starting to route %s:%hu -> %s:%hu", selfDesc.c_str(), srcAddr.c_str(), clientSrcPort, forwardAddr.c_str(), proxyRecord.forwardPort);
		ProxyTunnelWorkerData* tunnelDataA = new ProxyTunnelWorkerData();
		ProxyTunnelWorkerData* tunnelDataB = new ProxyTunnelWorkerData();
		tunnelDataA->sockA = clientSock;
		tunnelDataA->sockAAddr = clientSockIp;
		tunnelDataA->sockAPort = clientSrcPort;
		tunnelDataA->sockB = destSock;
		tunnelDataA->sockBAddr = proxyRecord.forwardAddr;
		tunnelDataA->sockBPort = proxyRecord.forwardPort;

		tunnelDataB->sockA = destSock;
		tunnelDataB->sockAAddr = proxyRecord.forwardAddr;
		tunnelDataB->sockAPort = proxyRecord.forwardPort;
		tunnelDataB->sockB = clientSock;
		tunnelDataB->sockBAddr = clientSockIp;
		tunnelDataB->sockBPort = clientSrcPort;
		std::thread tunnelThread(&ProxyTunnelWorker, tunnelDataA, this->selfDescStr);
		ProxyTunnelWorker(tunnelDataB, this->selfDescStr);
		tunnelThread.join();
	}

cleanup:
	if (clientSock != NULL)
		closesocket(clientSock);
	if (destSock != NULL)
		closesocket(destSock);

	info("%s: ProxyConnectionWorker exiting for client %s:%hu", selfDesc.c_str(), srcAddr.c_str(), clientSrcPort);
	return;
}

std::string InboundTCPDivertProxy::generateDivertFilterString()
{
	std::string result = "tcp";
	std::vector<std::string> orExpressions;
	std::string proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->localProxyPort) + ")";
	orExpressions.push_back(proxyFilterStr);

	if (this->containsSocksRecords)
	{
		proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->socksServer.GetPort()) + ")";
		orExpressions.push_back(proxyFilterStr);
	}

	//check for wildcard address
	bool containsWildcard = false;	
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == anyIpAddr)
		{
			std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + ")";
			orExpressions.push_back(recordFilterStr);
			containsWildcard = true;
			break;
		}
	}

	if (!containsWildcard)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			std::string srcAddrIpStr = this->getIpAddrIpStr(record->srcAddr);

			std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + " and " + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
			orExpressions.push_back(recordFilterStr);
		}
	}

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

bool InboundTCPDivertProxy::findProxyRecordBySrcAddr(IpAddr& srcAddr, InboundRelayEntry& proxyRecord)
{
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == anyIpAddr || record->srcAddr == srcAddr)
		{
			proxyRecord = *record;
			return true;
		}
	}
	return false;
}

bool InboundTCPDivertProxy::Stop()
{	
	info("%s: Stop", this->selfDescStr.c_str());
	{//lock scope
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		BaseProxy::Stop();
		if (this->proxySock != NULL)
		{
			shutdown(this->proxySock, SD_BOTH);
			closesocket(this->proxySock);
			this->proxySock = NULL;
		}
	}//lock scope

	if (this->proxyThread.joinable())
	{
		this->proxyThread.join();
	}
	if (this->socksServer.IsRunning())
	{
		return this->socksServer.Stop();
	}
	return true;
}

void InboundTCPDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
}

void InboundTCPDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
}

