#include "stdafx.h"
#include "BaseProxy.h"
#include"utils.h"
#include "windivert.h"
#include "ipaddr.h"


/*
* Cleanup completed I/O requests.
*/
static void cleanup(HANDLE ioport, OVERLAPPED* ignore)
{
	OVERLAPPED* overlapped;
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


void BaseProxy::logDebug(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	if (this->verbose)
	{
		std::string selfDesc = this->selfDescStr;
		std::string msgStr = selfDesc + " " + msg;
		vdebug(msgStr.c_str(), args);

	}
	va_end(args);
}

void BaseProxy::logInfo(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	std::string selfDesc = this->selfDescStr;
	std::string msgStr = selfDesc + " " + msg;
	vinfo(msgStr.c_str(), args);
	va_end(args);
}

void BaseProxy::logWarning(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	std::string selfDesc = this->selfDescStr;
	std::string msgStr = selfDesc + " " + msg;
	vwarning(msgStr.c_str(), args);	
	va_end(args);
}

void BaseProxy::logError(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	std::string selfDesc = this->selfDescStr;
	std::string msgStr = selfDesc + " " + msg;
	verror(msgStr.c_str(), args);
	va_end(args);
}

std::string BaseProxy::getIpAddrIpStr(IpAddr& addr)
{
	if (addr.get_family() == IPFamily::IPv4)
	{
		return "ip";
	}
	else if (addr.get_family() == IPFamily::IPv6)
	{
		return "ipv6";
	}
	return "Unknown";
}

std::string BaseProxy::getStringDesc()
{
	std::string result = std::string("BaseProxy()");
	return result;
}

std::string BaseProxy::generateDivertFilterString()
{
	return std::string("tcp");
}

void BaseProxy::SwapIPHeaderSrcToDst(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr)
{
	if (ip_hdr)
	{
		ip_hdr->DstAddr = ip_hdr->SrcAddr;
	}
	else if (ip6_hdr)
	{
		*(in6_addr*)&ip6_hdr->DstAddr[0] = *(in6_addr*)&ip6_hdr->SrcAddr[0];
	}
}

void BaseProxy::SwapIPHeaderDstToSrc(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr)
{
	if (ip_hdr)
	{
		ip_hdr->SrcAddr = ip_hdr->DstAddr;
	}
	else if (ip6_hdr)
	{
		*(in6_addr*)&ip6_hdr->SrcAddr[0] = *(in6_addr*)&ip6_hdr->DstAddr[0];
	}
}

void BaseProxy::OverrideIPHeaderSrc(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, IpAddr& addr)
{
	if (ip_hdr)
	{
		ip_hdr->SrcAddr = addr.get_ipv4_addr().S_un.S_addr;
	}
	else if (ip6_hdr)
	{
		*(in6_addr*)&ip6_hdr->SrcAddr[0] = addr.get_addr();
	}
}

void BaseProxy::OverrideIPHeaderDst(PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, IpAddr& addr)
{
	if (ip_hdr)
	{
		ip_hdr->DstAddr = addr.get_ipv4_addr().S_un.S_addr;
	}
	else if (ip6_hdr)
	{
		*(in6_addr*)&ip6_hdr->DstAddr[0] = addr.get_addr();
	}
}

void BaseProxy::DivertWorker()
{
	OVERLAPPED overlapped;
	OVERLAPPED* poverlapped;
	unsigned char packet[WINDIVERT_MTU_MAX];
	UINT packet_len = sizeof(packet);
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ip6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmp6_header;
	PWINDIVERT_UDPHDR udp_header;
	IpAddr srcIp;
	IpAddr dstIp;
	UINT addr_len = sizeof(WINDIVERT_ADDRESS);
	UINT recv_packet_len = 0;
	UINT recv_len = 0;
	DWORD len;
	UINT8 protocol;
	std::string selfDesc = this->getStringDesc();
	PacketAction action = PacketAction::STATUS_PROCEED;

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
				goto END;
			}
			else if (lastErr != ERROR_IO_PENDING)
			{
			read_failed:
				this->logWarning("failed to read packet (%d)", lastErr);
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

		if (WinDivertHelperParsePacket(&packet[0], recv_packet_len, &ip_header, &ip6_header, &protocol, &icmp_header, &icmp6_header, &tcp_header, &udp_header, NULL, NULL, NULL, NULL))
		{
			bool packet_contains_iphdr = true;
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
				memcpy(&temp_addr.u.Byte[0], ip6_header->SrcAddr, sizeof(in6_addr));
				srcIp = IpAddr(temp_addr);
				memcpy(&temp_addr.u.Byte[0], ip6_header->DstAddr, sizeof(in6_addr));
				dstIp = IpAddr(temp_addr);
			}
			else
			{
				packet_contains_iphdr = false;
				this->logError("No IP header in packet!?");
			}

			if (packet_contains_iphdr)
			{
				std::string srcIpStr = srcIp.to_string();
				std::string dstIpStr = dstIp.to_string();
				std::string direction_str = addr.Outbound == 1 ? "OUT" : "IN";

				if (protocol == IPPROTO_TCP)
				{
					UINT16 srcPort = ntohs(tcp_header->SrcPort);
					UINT16 dstPort = ntohs(tcp_header->DstPort);
					this->logDebug("TCP Packet %s:%hu %s:%hu %s", srcIpStr.c_str(), srcPort, dstIpStr.c_str(), dstPort, direction_str.c_str());
					action = this->ProcessTCPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header, tcp_header, srcIp, dstIp);
				}
				else if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
				{
					this->logDebug("ICMP Packet %s %s %s", srcIpStr.c_str(), dstIpStr.c_str(), direction_str.c_str());
					action = this->ProcessICMPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header, icmp_header, icmp6_header, srcIp, dstIp);
				}
				else if (protocol == IPPROTO_UDP)
				{
					UINT16 srcPort = ntohs(udp_header->SrcPort);
					UINT16 dstPort = ntohs(udp_header->DstPort);
					this->logDebug("UDP Packet %s:%hu %s:%hu %s", srcIpStr.c_str(), srcPort, dstIpStr.c_str(), dstPort, direction_str.c_str());
					action = this->ProcessUDPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header, udp_header, srcIp, dstIp);
				}
			}
		}
		else
		{
			this->logWarning("failed to parse packet (%d)", GetLastError());
		}

		if (action == PacketAction::STATUS_PROCEED)
		{
			if (!WinDivertHelperCalcChecksums(&packet[0], recv_packet_len, &addr, 0))
			{
				this->logError("failed to recalc packet checksum: (%d)", GetLastError());
			}
			poverlapped = (OVERLAPPED*)malloc(sizeof(OVERLAPPED));
			if (poverlapped == NULL)
			{
				error("%s: failed to allocate poverlapped memory", selfDesc.c_str());
			}
			memset(poverlapped, 0, sizeof(OVERLAPPED));
			if (WinDivertSendEx(this->hDivert, &packet[0], recv_packet_len, NULL, 0, &addr, addr_len, poverlapped))
			{
				continue;
			}
			if (GetLastError() != ERROR_IO_PENDING)
			{
				this->logWarning("failed to send packet (%d)", GetLastError());
				continue;
			}
		}
		else
		{
			this->logDebug("Dropping packet");
		}
	}
END:
	this->logInfo("DivertWorker exiting");
	return;
}

BaseProxy::BaseProxy(bool verbose)
{
	this->running = false;
	this->priority = 0;
	this->selfDescStr = this->getStringDesc();
	this->verbose = verbose;
}


BaseProxy::~BaseProxy()
{
	if (this->running)
	{
		this->Stop();
	}
}

bool BaseProxy::Start()
{
	//lock scope
	{
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		this->logInfo("Start");

		this->ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (this->ioPort == NULL)
		{
			this->logError("failed to create I/O completion port (%d)", GetLastError());
			goto failure;
		}

		this->event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (event == NULL)
		{
			this->logError("failed to create event (%d)", GetLastError());
			goto failure;
		}

		this->filterStr = this->generateDivertFilterString();
		this->logInfo("%s", this->filterStr.c_str());
		this->hDivert = WinDivertOpen(this->filterStr.c_str(), WINDIVERT_LAYER_NETWORK, this->priority, 0);
		if (this->hDivert == INVALID_HANDLE_VALUE)
		{
			this->logError("failed to open the WinDivert device (%d)", GetLastError());
			goto failure;
		}
		if (CreateIoCompletionPort(this->hDivert, this->ioPort, 0, 0) == NULL)
		{
			this->logError("failed to associate I/O completion port (%d)", GetLastError());
			goto failure;
		}
	}//lock scope

	this->running = true;
	this->divertThread = std::thread(&BaseProxy::DivertWorker, this);
	return true;

failure:
	this->Stop();
	return false;
}

bool BaseProxy::Stop()
{
	this->logInfo("Stop");
	{//lock scope
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		this->running = false;
		if (this->hDivert != NULL)
		{
			WinDivertClose(this->hDivert);
			this->hDivert = NULL;
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
	return true;
}
