#include "stdafx.h"
#include "BaseProxy.h"
#include"utils.h"
#include "windivert.h"
#include "ipaddr.h"


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


std::string BaseProxy::getStringDesc()
{	
	std::string result = std::string("BaseProxy()");
	return result;	
}

std::string BaseProxy::generateDivertFilterString()
{
	return std::string("tcp");
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
				error("%s: No IP header in packet!?", selfDesc.c_str());
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
					info("%s: TCP Packet %s:%hu %s:%hu %s", selfDesc.c_str(), srcIpStr.c_str(), srcPort, dstIpStr.c_str(), dstPort, direction_str.c_str());										
					this->ProcessTCPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header,  tcp_header, srcIp, dstIp);
				}
				else if(protocol == IPPROTO_ICMP  || protocol == IPPROTO_ICMPV6)
				{			
					info("%s: ICMP Packet %s %s %s", selfDesc.c_str(), srcIpStr.c_str(), dstIpStr.c_str(), direction_str.c_str());
					this->ProcessICMPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header, icmp_header, icmp6_header, srcIp, dstIp);
				}
				else if (protocol == IPPROTO_UDP)
				{
					UINT16 srcPort = ntohs(udp_header->SrcPort);
					UINT16 dstPort = ntohs(udp_header->DstPort);
					info("%s: UDP Packet %s:%hu %s:%hu %s", selfDesc.c_str(), srcIpStr.c_str(), srcPort, dstIpStr.c_str(), dstPort, direction_str.c_str());
					this->ProcessUDPPacket(&packet[0], recv_packet_len, &addr, ip_header, ip6_header, udp_header, srcIp, dstIp);
				}
			}
		}
		else
		{
			warning("%s: failed to parse packet (%d)", selfDesc.c_str(), GetLastError());
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
		if (WinDivertSendEx(this->hDivert, &packet[0], recv_packet_len, NULL, 0, &addr, addr_len, poverlapped))
		{
			continue;
		}
		if (GetLastError() != ERROR_IO_PENDING)
		{
			warning("%s: failed to send packet (%d)", selfDesc.c_str(), GetLastError());
			continue;
		}
	}
END:
	info("%s: DivertWorker exiting", selfDesc.c_str());
	return;
}

BaseProxy::BaseProxy()
{
	this->running = false;	
	this->priority = 0;
	this->selfDescStr = this->getStringDesc();
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
		info("%s: Start", this->selfDescStr.c_str());
		
		this->ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (this->ioPort == NULL)
		{
			error("%s: failed to create I/O completion port (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}

		this->event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (event == NULL)
		{
			error("%s: failed to create event (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}

		this->filterStr = this->generateDivertFilterString();
		info("%s: %s", this->selfDescStr.c_str(), this->filterStr.c_str());
		this->hDivert = WinDivertOpen(this->filterStr.c_str(), WINDIVERT_LAYER_NETWORK, this->priority, 0);
		if (this->hDivert == INVALID_HANDLE_VALUE)
		{
			error("%s: failed to open the WinDivert device (%d)", this->selfDescStr.c_str(), GetLastError());
			goto failure;
		}
		if (CreateIoCompletionPort(this->hDivert, this->ioPort, 0, 0) == NULL)
		{
			error("%s: failed to associate I/O completion port (%d)", this->selfDescStr.c_str(), GetLastError());
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
	info("%s: Stop", this->selfDescStr.c_str());
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
