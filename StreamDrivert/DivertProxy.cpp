#include "stdafx.h"
#include "DivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>

/*
* Cleanup completed I/O requests.
*/
static void cleanup(HANDLE ioport, OVERLAPPED *ignore)
{
	OVERLAPPED *overlapped;
	DWORD iolen;
	ULONG_PTR iokey = 0;

	while (GetQueuedCompletionStatus(ioport, &iolen, &iokey, &overlapped, 0))
	{
		if (overlapped != ignore)
		{
			free(overlapped);
		}
	}
}

DivertProxy::DivertProxy(const UINT16 localPort, const std::vector<RelayEntry>& proxyRecords)
{
	this->running = false;
	this->localPort = localPort;
	this->localProxyPort = 0;
	this->proxyRecords = proxyRecords;
	this->proxySock = NULL;
	this->priority = 0;
}

DivertProxy::~DivertProxy()
{
	if (this->running)
	{
		this->Stop();
	}
}

bool DivertProxy::Start()
{
	WSADATA wsa_data;
	WORD wsa_version = MAKEWORD(2, 2);
	int on = 1;
	int off = 0;
	struct sockaddr_in6 addr;

	//lock scope
	{
		std::lock_guard<std::mutex> lock(this->resourceLock);
		std::string selfDesc = this->getStringDesc();
		info("%s: Start", selfDesc.c_str());

		if (WSAStartup(wsa_version, &wsa_data) != 0)
		{
			error("%s: failed to start WSA (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}
		this->proxySock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (this->proxySock == INVALID_SOCKET)
		{
			error("%s: failed to create socket (%d)", selfDesc.c_str(), WSAGetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int)) == SOCKET_ERROR)
		{
			error("%s: failed to re-use address (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
		{
			error("%s: failed to set socket dual-stack (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(0);
		addr.sin6_addr = in6addr_any;
		//inet_pton(AF_INET6, "::1", &addr.sin6_addr);
		if (::bind(this->proxySock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			error("%s: failed to bind socket (%d)", selfDesc.c_str(), WSAGetLastError());
			goto failure;
		}

		struct sockaddr_in6 bind_addr;
		int bind_addr_len = sizeof(bind_addr);
		if (getsockname(this->proxySock, (struct sockaddr *)&bind_addr, &bind_addr_len) == -1)
		{
			error("%s: failed to get bind socket port (%d)", selfDesc.c_str(), WSAGetLastError());
		}
		this->localProxyPort = ntohs(bind_addr.sin6_port);


		if (listen(this->proxySock, 16) == SOCKET_ERROR)
		{
			error("%s: failed to listen socket (%d)", selfDesc.c_str(), WSAGetLastError());
			goto failure;
		}

		selfDesc = this->getStringDesc();
		std::string fiendlyProxyRecordStr = this->getFiendlyProxyRecordsStr();
		info("%s: Start divertion of:\n%s", selfDesc.c_str(), fiendlyProxyRecordStr.c_str());
		this->ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (this->ioPort == NULL)
		{
			error("%s: failed to create I/O completion port (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}

		this->event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (event == NULL)
		{
			error("%s: failed to create event (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}

		this->filterStr = this->generateDivertFilterString();
		info("%s: %s", selfDesc.c_str(), this->filterStr.c_str());
		this->hDivert = WinDivertOpen(this->filterStr.c_str(), WINDIVERT_LAYER_NETWORK, this->priority, 0);
		if (this->hDivert == INVALID_HANDLE_VALUE)
		{
			error("%s: failed to open the WinDivert device (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}
		if (CreateIoCompletionPort(this->hDivert, this->ioPort, 0, 0) == NULL)
		{
			error("%s: failed to associate I/O completion port (%d)", selfDesc.c_str(), GetLastError());
			goto failure;
		}
	}//lock scope

	this->running = true;
	this->proxyThread = std::thread(&DivertProxy::ProxyWorker, this);
	this->divertThread = std::thread(&DivertProxy::DivertWorker, this);
	return true;

failure:
	this->Stop();
	return false;
}


std::string DivertProxy::getFiendlyProxyRecordsStr()
{
	std::string result;
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		std::string srcip = record->srcAddr.to_string();
		result += srcip + ":" + std::to_string(this->localPort) + " -> " + srcip + ":" + std::to_string(this->localProxyPort) + " -> " + record->forwardAddr.to_string() + ":" + std::to_string(record->forwardPort) + "\n";
	}
	return result;
}

std::string DivertProxy::getStringDesc()
{
	std::string result = std::string("DivertProxy(" + std::to_string(this->localPort) + ":");
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

void DivertProxy::DivertWorker()
{
	OVERLAPPED overlapped;
	OVERLAPPED* poverlapped;	
	unsigned char packet[WINDIVERT_MTU_MAX];
	UINT packet_len = sizeof(packet);
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ip6_header;
	PWINDIVERT_TCPHDR tcp_header;
	IpAddr srcIp;
	IpAddr dstIp;
	UINT addr_len = sizeof(WINDIVERT_ADDRESS);
	UINT recv_packet_len = 0;
	UINT recv_len = 0;
	DWORD len;
	UINT8 protocol;
	std::string selfDesc = this->getStringDesc();

	while (TRUE)
	{
		memset(&overlapped, 0, sizeof(overlapped));
		ResetEvent(this->event);
		overlapped.hEvent = this->event;
		if (!WinDivertRecvEx(this->hDivert, &packet[0], packet_len, &recv_len, 0, &addr, &addr_len, &overlapped))
		{
			DWORD lastErr = GetLastError();
			if (lastErr == ERROR_INVALID_HANDLE || lastErr == ERROR_OPERATION_ABORTED)
			{
				//error("%s: WinDivertRecvEx failed: (%d)", selfDesc.c_str(), lastErr);
				goto end;
			}
			else if (lastErr != ERROR_IO_PENDING)
			{
			read_failed:
				warning("%s: failed to read packet (%d)", selfDesc.c_str(), lastErr);
				continue;
			}

			// Timeout = 1s
			while (WaitForSingleObject(event, 1000) == WAIT_TIMEOUT)
			{
				cleanup(this->ioPort, &overlapped);
			}
			if (!GetOverlappedResult(this->hDivert, &overlapped, &len, FALSE))
			{
				goto read_failed;
			}
			recv_packet_len = len;
		}
		cleanup(this->ioPort, &overlapped);

		if (!WinDivertHelperParsePacket(&packet[0], recv_packet_len, &ip_header, &ip6_header, &protocol, NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL))
		{
			warning("%s: failed to parse packet (%d)", selfDesc.c_str(), GetLastError());
			continue;
		}
		
		if (ip_header != NULL)
		{
			in_addr temp_addr;
			temp_addr.S_un.S_addr = ip_header->SrcAddr;
			srcIp = IpAddr(temp_addr);
			temp_addr.S_un.S_addr = ip_header->DstAddr;
			dstIp = IpAddr(temp_addr);
		}
		else if (ip6_header != NULL)
		{
			in6_addr temp_addr;
			memcpy(ip6_header->SrcAddr, &temp_addr.u.Byte[0], sizeof(in6_addr));
			srcIp = IpAddr(temp_addr);
			memcpy(ip6_header->DstAddr, &temp_addr.u.Byte[0], sizeof(in6_addr));
			dstIp = IpAddr(temp_addr);
		}

		std::string srcIpStr = srcIp.to_string();
		std::string dstIpStr = dstIp.to_string();
		
		UINT16 srcPort = ntohs(tcp_header->SrcPort);
		UINT16 dstPort = ntohs(tcp_header->DstPort);
		std::string direction_str = addr.Outbound == 1 ? "OUT" : "IN";
		info("%s: Packet %s:%hu %s:%hu %s", selfDesc.c_str(), srcIpStr.c_str(), srcPort, dstIpStr.c_str(), dstPort, direction_str.c_str());

		if (true)
		{
			if (addr.Outbound == 1)
			{
				for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
				{
					if (dstIp == record->srcAddr &&
						tcp_header->SrcPort == htons(this->localProxyPort))
					{
						info("%s: Modify packet src -> %s:%hu", selfDesc.c_str(), dstIpStr.c_str(), this->localPort);
						tcp_header->SrcPort = htons(this->localPort);
					}
				}
			}
			else
			{
				for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
				{
					if (srcIp == record->srcAddr &&
						tcp_header->DstPort == htons(this->localPort))
					{
						info("%s: Modify packet dst -> %s:%hu", selfDesc.c_str(), dstIpStr.c_str(), this->localProxyPort);
						tcp_header->DstPort = htons(this->localProxyPort);
					}
				}
			}
		}

		if (!WinDivertHelperCalcChecksums(&packet[0], recv_packet_len, &addr, 0))
		{
			error("%s: failed to recalc packet checksum: (%d)", selfDesc.c_str(), GetLastError());
		}
		poverlapped = (OVERLAPPED *)malloc(sizeof(OVERLAPPED));
		if (poverlapped == NULL)
		{
			error("%s: failed to allocate poverlapped memory", selfDesc.c_str());
		}
		memset(poverlapped, 0, sizeof(OVERLAPPED));
		if (WinDivertSendEx(this->hDivert, &packet[0], recv_packet_len, NULL, 0, &addr, addr_len , poverlapped))
		{
			continue;
		}
		if (GetLastError() != ERROR_IO_PENDING)
		{
			warning("%s: failed to send packet (%d)", selfDesc.c_str(), GetLastError());
			continue;
		}
	}
end:
	info("%s: DivertWorker exiting", selfDesc.c_str());
	return;
}

void DivertProxy::ProxyWorker()
{
	std::string selfDesc = this->getStringDesc();
	while (true)
	{
		struct sockaddr_in6  clientSockAddr;
		int size = sizeof(clientSockAddr);
		SOCKET incommingSock = accept(this->proxySock, (SOCKADDR *)&clientSockAddr, &size);
		if (incommingSock == INVALID_SOCKET)
		{
			std::lock_guard<std::mutex> lock(this->resourceLock);
			if (this->running == false)
			{
				goto cleanup;
			}
			warning("%s: failed to accept socket (%d)", selfDesc.c_str(), WSAGetLastError());
			continue;
		}
		IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
		std::string srcAddr = clientSockIp.to_string();
		info("%s: Incoming connection from %s:%hu", selfDesc.c_str(), srcAddr.c_str(), ntohs(clientSockAddr.sin6_port));
		ProxyConnectionWorkerData* proxyConnectionWorkerData = new ProxyConnectionWorkerData();
		proxyConnectionWorkerData->clientSock = incommingSock;
		proxyConnectionWorkerData->clientAddr = clientSockAddr;
		std::thread proxyConnectionThread(&DivertProxy::ProxyConnectionWorker, this, proxyConnectionWorkerData);
		proxyConnectionThread.detach();
	}
cleanup:
	if (this->proxySock != NULL)
	{
		closesocket(this->proxySock);
		this->proxySock = NULL;
	}
	info("%s: ProxyWorker exiting", selfDesc.c_str());
}

void DivertProxy::ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData)
{
	int off = 0;
	SOCKET destSock = NULL;
	SOCKET clientSock = proxyConnectionWorkerData->clientSock;
	sockaddr_in6 clientSockAddr = proxyConnectionWorkerData->clientAddr;
	IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
	delete proxyConnectionWorkerData;

	std::string selfDesc = this->getStringDesc();

	RelayEntry proxyRecord;
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
		std::thread tunnelThread(&DivertProxy::ProxyTunnelWorker, this, tunnelDataA);
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

void DivertProxy::ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData)
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
				shutdown(sockA, SD_BOTH);
				shutdown(sockB, SD_BOTH);
				goto end; //return
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

std::string DivertProxy::generateDivertFilterString()
{
	std::string result = "tcp";
	std::vector<std::string> orExpressions;
	std::string proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->localProxyPort) + ")";
	orExpressions.push_back(proxyFilterStr);

	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + " and ip.SrcAddr == " + record->srcAddr.to_string() + ")";
		orExpressions.push_back(recordFilterStr);
	}

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

bool DivertProxy::findProxyRecordBySrcAddr(IpAddr& srcAddr, RelayEntry& proxyRecord)
{
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == srcAddr)
		{
			proxyRecord = *record;
			return true;
		}
	}
	return false;
}

bool DivertProxy::Stop()
{
	std::string selfDesc = this->getStringDesc();
	info("%s: Stop", selfDesc.c_str());
	{//lock scope
		std::lock_guard<std::mutex> lock(this->resourceLock);
		this->running = false;
		if (this->hDivert != NULL)
		{
			WinDivertClose(this->hDivert);
			this->hDivert = NULL;
		}
		if (this->proxySock != NULL)
		{
			shutdown(this->proxySock, SD_BOTH);
			closesocket(this->proxySock);
			this->proxySock = NULL;
		}
		if (this->ioPort != NULL)
		{
			CloseHandle(this->ioPort);
			this->ioPort = NULL;
		}
		if (this->event != NULL)
		{
			CloseHandle(this->event);
			this->event = NULL;
		}
	}//lock scope

	if (this->divertThread.joinable())
	{
		this->divertThread.join();
	}
	if (this->proxyThread.joinable())
	{
		this->proxyThread.join();
	}

	return true;
}

