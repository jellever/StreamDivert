#include "stdafx.h"
#include "sockutils.h"
#include <winsock2.h>
#include "utils.h"


int recvall(SOCKET sock, char* buffer, int len)
{
	char* dataPtr = buffer;
	int totalRead = 0;
	while (totalRead < len)
	{
		int read = recv(sock, dataPtr, len - totalRead, 0);
		if(read == 0 || read == SOCKET_ERROR)
		{
			break;
		}
		totalRead += read;
		dataPtr += read;
	}
	return totalRead;
}

bool recvallb(SOCKET sock, char* buffer, int len)
{
	return recvall(sock, buffer, len) == len;
}

int sendall(SOCKET sock, const char* buffer, int len)
{
	const char* dataPtr = buffer;
	int totalSent = 0;
	while (totalSent < len)
	{
		int sent = send(sock, dataPtr, len - totalSent, 0);
		if (sent == SOCKET_ERROR)
		{
			break;
		}
		totalSent += sent;
		dataPtr += sent;
	}
	return totalSent;
}

bool sendallb(SOCKET sock, const char* buffer, int len)
{
	return sendall(sock, buffer, len) == len;
}

bool recvstr(SOCKET sock, char* buf, int* len)
{
	int totalRead = 0;
	int read = 0;
	while (totalRead < *len)
	{
		read = recv(sock, buf + totalRead, 1, 0);
		if (read == 0 || read == SOCKET_ERROR)
		{
			return false;
		}
		if (*(buf + totalRead) == 0)
		{
			return true;
		}
	}
	return false;
}

void ProxyTunnelWorker(ProxyTunnelWorkerData* proxyTunnelWorkerData, std::string& logDesc)
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

	info("Tunneling %s:%d -> %s:%d", sockAAddrStr.c_str(), sockAPort, sockBAddrStr.c_str(), sockBPort);

	while (true)
	{
		recvLen = recv(sockA, buf, sizeof(buf), 0);
		if (recvLen == SOCKET_ERROR)
		{
			warning("%s: failed to recv from socket A(%s:%hu): %d", logDesc.c_str(), sockAAddrStr.c_str(), sockAPort, WSAGetLastError());
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
				warning("%s: failed to send to socket B(%s:%hu): %d", logDesc.c_str(), sockBAddrStr.c_str(), sockBPort, WSAGetLastError());
				goto failure; //return
			}
			i += sendLen;
		}
	}

failure:
	shutdown(sockA, SD_BOTH);
	shutdown(sockB, SD_BOTH);
end:
	info("%s: ProxyTunnelWorker(%s:%hu -> %s:%hu) exiting", logDesc.c_str(), sockAAddrStr.c_str(), sockAPort, sockBAddrStr.c_str(), sockBPort);
}