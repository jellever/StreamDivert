#include "stdafx.h"
#include "InboundDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>


InboundDivertProxy::InboundDivertProxy(const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords)
{	
	this->localPort = localPort;
	this->localProxyPort = 0;
	this->proxyRecords = proxyRecords;
	this->proxySock = NULL;
	this->selfDescStr = this->getStringDesc();
}

InboundDivertProxy::~InboundDivertProxy()
{
	if (this->running)
	{
		this->Stop();
	}
}

bool InboundDivertProxy::Start()
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

		BaseProxy::Start();
	}//lock scope

	this->proxyThread = std::thread(&InboundDivertProxy::ProxyWorker, this);
	return true;

failure:
	this->Stop();
	return false;
}


std::string InboundDivertProxy::getFiendlyProxyRecordsStr()
{
	std::string result;
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		std::string srcip = record->srcAddr.to_string();
		result += srcip + ":" + std::to_string(this->localPort) + " -> " + srcip + ":" + std::to_string(this->localProxyPort) + " -> " + record->forwardAddr.to_string() + ":" + std::to_string(record->forwardPort) + "\n";
	}
	return result;
}

std::string InboundDivertProxy::getStringDesc()
{
	std::string result = std::string("InboundDivertProxy(" + std::to_string(this->localPort) + ":");
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

void InboundDivertProxy::ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, UINT8 protocol, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr)
{
	if (true)
	{
		if (addr->Outbound == 1)
		{
			for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
			{
				if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr) &&
					tcp_hdr->SrcPort == htons(this->localProxyPort))
				{
					std::string dstAddrStr = dstAddr.to_string();
					info("%s: Modify packet src -> %s:%hu", this->selfDescStr.c_str(), dstAddrStr.c_str(), this->localPort);
					tcp_hdr->SrcPort = htons(this->localPort);
				}
			}
		}
		else
		{
			for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
			{
				if ((srcAddr == record->srcAddr || record->srcAddr == anyIpAddr) &&
					tcp_hdr->DstPort == htons(this->localPort))
				{
					std::string dstAddrStr = dstAddr.to_string();
					info("%s: Modify packet dst -> %s:%hu", this->selfDescStr.c_str(), dstAddrStr.c_str(), this->localProxyPort);
					tcp_hdr->DstPort = htons(this->localProxyPort);
				}
			}
		}
	}
}



void InboundDivertProxy::ProxyWorker()
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
		std::thread proxyConnectionThread(&InboundDivertProxy::ProxyConnectionWorker, this, proxyConnectionWorkerData);
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

void InboundDivertProxy::ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData)
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
		std::thread tunnelThread(&InboundDivertProxy::ProxyTunnelWorker, this, tunnelDataA);
		this->ProxyTunnelWorker(tunnelDataB);
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

void InboundDivertProxy::ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData)
{
	SOCKET sockA = proxyTunnelWorkerData->sockA;
	std::string sockAAddrStr = proxyTunnelWorkerData->sockAAddr.to_string();
	UINT16 sockAPort = proxyTunnelWorkerData->sockAPort;
	SOCKET sockB = proxyTunnelWorkerData->sockB;
	std::string sockBAddrStr = proxyTunnelWorkerData->sockBAddr.to_string();
	UINT16 sockBPort = proxyTunnelWorkerData->sockBPort;
	delete proxyTunnelWorkerData;
	char buf[8192];
	int recvLen;
	std::string selfDesc = this->getStringDesc();
	while (true)
	{
		recvLen = recv(sockA, buf, sizeof(buf), 0);
		if (recvLen == SOCKET_ERROR)
		{
			warning("%s: failed to recv from socket A(%s:%hu): %d", selfDesc.c_str(), sockAAddrStr.c_str(), sockAPort, WSAGetLastError());
			goto failure;
		}
		if (recvLen == 0)
		{
			shutdown(sockA, SD_RECEIVE);
			shutdown(sockB, SD_SEND);
			goto end; //return
		}

		for (int i = 0; i < recvLen; )
		{
			int sendLen = send(sockB, buf + i, recvLen - i, 0);
			if (sendLen == SOCKET_ERROR)
			{
				warning("%s: failed to send to socket B(%s:%hu): %d", selfDesc.c_str(), sockBAddrStr.c_str(), sockBPort, WSAGetLastError());				
				goto failure; //return
			}
			i += sendLen;
		}
	}

failure:
	shutdown(sockA, SD_BOTH);
	shutdown(sockB, SD_BOTH);
end:
	info("%s: ProxyTunnelWorker(%s:%hu -> %s:%hu) exiting", selfDesc.c_str(), sockAAddrStr.c_str(), sockAPort, sockBAddrStr.c_str(), sockBPort);
}

std::string InboundDivertProxy::generateDivertFilterString()
{
	std::string result = "tcp";
	std::vector<std::string> orExpressions;
	std::string proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->localProxyPort) + ")";
	orExpressions.push_back(proxyFilterStr);

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
			if (record->srcAddr.get_family() == IPFamily::IPv4)
			{
				std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + " and ip.SrcAddr == " + record->srcAddr.to_string() + ")";
				orExpressions.push_back(recordFilterStr);
			}
			else if (record->srcAddr.get_family() == IPFamily::IPv6)
			{
				std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + " and ipv6.SrcAddr == " + record->srcAddr.to_string() + ")";
				orExpressions.push_back(recordFilterStr);
			}
		}
	}

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

bool InboundDivertProxy::findProxyRecordBySrcAddr(IpAddr& srcAddr, InboundRelayEntry& proxyRecord)
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

bool InboundDivertProxy::Stop()
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

	return true;
}

