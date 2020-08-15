#include "stdafx.h"
#include "SocksProxyServer.h"
#include "utils.h"
#include <ws2tcpip.h>
#include <Winsock2.h>
#include "ipaddr.h"
#include "sockutils.h"


SocksProxyServer::SocksProxyServer(int port, bool enableSocks4, bool enableSocks5)
{
	this->port = port;
	this->serverSock = INVALID_SOCKET;
	this->selfDescStr = this->getSelfDescription();
	this->running = false;
	this->socks5AuthType = Socks5AuthMethods::NOAUTH;
	this->username = "";
	this->password = "";
	this->enableSocks4 = enableSocks4;
	this->enableSocks5 = enableSocks5;
}

SocksProxyServer::SocksProxyServer(int port)
	: SocksProxyServer(port, true, true)
{
}

SocksProxyServer::~SocksProxyServer()
{
}

void SocksProxyServer::SetAuthType(Socks5AuthMethods method)
{
	this->socks5AuthType = method;
}

void SocksProxyServer::SetAuthUsername(std::string& username)
{
	this->username = username;
}

void SocksProxyServer::SetAuthPassword(std::string& password)
{
	this->password = password;
}

int SocksProxyServer::GetPort()
{
	return this->port;
}


std::string SocksProxyServer::getSelfDescription()
{
	return "SocksProxyServer(" + std::to_string(this->port) + ")";
}

void SocksProxyServer::ProxyServerWorker()
{
	while (true)
	{
		struct sockaddr_in6  clientSockAddr;
		int size = sizeof(clientSockAddr);
		SOCKET incommingSock = accept(this->serverSock, (SOCKADDR*)&clientSockAddr, &size);
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

		int one = 1;
		setsockopt(incommingSock, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));

		SocksServerConnectionData* proxyConnectionWorkerData = new SocksServerConnectionData();
		proxyConnectionWorkerData->clientSocket = incommingSock;
		proxyConnectionWorkerData->clientAddr = clientSockAddr;
		std::thread proxyConnectionThread(&SocksProxyServer::ProxyConnectionWorker, this, proxyConnectionWorkerData);
		proxyConnectionThread.detach();
	}
cleanup:
	if (this->serverSock != NULL)
	{
		closesocket(this->serverSock);
		this->serverSock = NULL;
	}
	info("%s: ProxyServerWorker exiting", this->selfDescStr.c_str());
}

SOCKET SocksProxyServer::ProcessSocks4Connection(SOCKET sock)
{
	SOCKET proxySock = INVALID_SOCKET;
	char cmd;
	int received = 0;
	received = recvall(sock, &cmd, 1);
	if (cmd == CMD_CONNECT)
	{
		unsigned short int port;
		in_addr ipv4AddrStore;
		IpAddr ipv4Addr;
		char userid[1024];
		char domain[1024];
		int useridLen, domainLen;
		useridLen = sizeof(userid);
		domainLen = sizeof(domain);
		if (!recvallb(sock, (char*)&port, sizeof(port)))
		{
			return false;
		}
		port = ntohs(port);
		if (!recvallb(sock, (char*)&ipv4AddrStore.S_un.S_addr, sizeof(ipv4AddrStore.S_un.S_addr)))
		{
			return false;
		}
		if (!recvstr(sock, &userid[0], &useridLen))
		{
			return false;
		}

		if (this->socks4aIsInvalidIpv4(ipv4AddrStore.S_un.S_addr))
		{
			if (!recvstr(sock, &domain[0], &domainLen))
			{
				return false;
			}
			proxySock = SocksProxyServer::socksConnect(std::string(&domain[0]), port);
		}
		else
		{
			ipv4Addr = IpAddr(ipv4AddrStore);
			proxySock = SocksProxyServer::socksConnect(ipv4Addr, port);
		}
		if (proxySock != INVALID_SOCKET)
		{
			this->socks4aSendClientResponse(sock, Socks4aClientResponse::RequestGranted);
		}
		else
		{
			this->socks4aSendClientResponse(sock, Socks4aClientResponse::RequestRejectedOrFailed);
		}
	}
	else
	{
		error("Unsupported socks4 cmd: %hhi", cmd);		
	}
	return proxySock;
}

SOCKET SocksProxyServer::ProcessSocks5Connection(SOCKET sock)
{
	SOCKET proxySock = INVALID_SOCKET;
	char methods;
	char buffer[4];
	IpAddr ipAddr;
	std::string domain;
	unsigned short int port;
	Socks5AddressType addrType;

	if (!recvallb(sock, &methods, 1))
	{
		goto failure;
	}
	if (!this->socks5Auth(sock, methods))
	{
		goto failure;
	}

	/*
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	
	if (!recvallb(sock, &buffer[0], sizeof(buffer)))
	{
		goto failure;
	}
	if (buffer[0] != SocksVersion::Socks5)
	{
		goto failure;
	}
	if (buffer[1] != CMD_CONNECT) //Others not supported
	{
		goto failure;
	}
	
	addrType = (Socks5AddressType)buffer[3];
	if (addrType == Socks5AddressType::AddrTypeIPv4)
	{
		in_addr addr;		
		if (!recvallb(sock, (char*)&addr.S_un.S_addr, sizeof(addr)))
		{
			goto failure;
		}
		if (!recvallb(sock, (char*)&port, sizeof(port)))
		{
			goto failure;
		}
		port = ntohs(port);
		ipAddr = IpAddr(addr);
		proxySock = this->socksConnect(ipAddr, port);		
	}
	else if (addrType == Socks5AddressType::AddrTypeIPv6)
	{
		in6_addr addr;
		if (!recvallb(sock, (char*)&addr.u.Byte, sizeof(addr)))
		{
			goto failure;
		}
		if (!recvallb(sock, (char*)&port, sizeof(port)))
		{
			goto failure;
		}
		port = ntohs(port);
		ipAddr = IpAddr(addr);
		proxySock = this->socksConnect(ipAddr, port);
	}
	else if (addrType == Socks5AddressType::AddrTypeDomainName)
	{
		unsigned char domainLen;
		char domainBuf[1024];		
		if (!recvallb(sock, (char*)&domainLen, sizeof(domainLen)))
		{
			goto failure;
		}
		if (!recvallb(sock, (char*)&domainBuf[0], domainLen))
		{
			goto failure;
		}		
		if (!recvallb(sock, (char*)&port, sizeof(port)))
		{
			goto failure;
		}
		port = ntohs(port);
		domainBuf[domainLen] = 0;
		domain = std::string(domainBuf);
		proxySock = this->socksConnect(domain, port);
	}

	if (proxySock != INVALID_SOCKET)
	{
		if (this->socks5SendClientResponse(sock, Socks5ClientResponse::succeeded, addrType, &ipAddr, &domain, port))
		{
			return proxySock;
		}
	}

failure:
	closesocket(proxySock);
	return INVALID_SOCKET;
}

bool SocksProxyServer::socks5Auth(SOCKET sock, int methods)
{
	bool supported = false;
	for (int i = 0; i < methods; i++) {
		char type;
		recvallb(sock, (char*)&type, 1);		
		if (type == this->socks5AuthType) {
			supported = true;			
		}
	}
	if (!supported) {
		this->socks5SendAuthNotSupported(sock);
		return false;
	}	
	switch (this->socks5AuthType) {
	case Socks5AuthMethods::NOAUTH:
		this->socks5SendNoAth(sock);
		return true;
		break;
	case Socks5AuthMethods::USERPASS:
		return this->socks5UserPassAuthentication(sock);
		break;
	}
	return false;
}

void SocksProxyServer::socks5SendAuthNotSupported(SOCKET sock)
{
	char answer[2] = { (char)SocksVersion::Socks5 , Socks5AuthMethods::NOMETHOD };
	sendallb(sock, answer, sizeof(answer));
}

void SocksProxyServer::socks5SendNoAth(SOCKET sock)
{
	char answer[2] = { (char)SocksVersion::Socks5, Socks5AuthMethods::NOAUTH };
	sendallb(sock, answer, sizeof(answer));
}

bool SocksProxyServer::socks5UserPassAuthentication(SOCKET sock)
{
	char answer[2] = { (char)SocksVersion::Socks5, Socks5AuthMethods::USERPASS };
	if (!sendallb(sock, answer, sizeof(answer))) {
		return false;
	}

	/*
	+----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
	*/
	char ver;
	if (!recvallb(sock, &ver, sizeof(ver)))
	{
		return false;
	}
	if (ver != AUTH_VERSION)
	{
		return false;
	}
	std::string username;
	std::string password;
	if (!this->socks5GetUserPassStr(sock, username))
	{
		return false;
	}
	if (!this->socks5GetUserPassStr(sock, password))
	{
		return false;
	}
	if (username == this->username && password == this->password)
	{
		char authokResp[2] = { AUTH_VERSION, Socks5UserPassAuth::AuthOk };
		return sendallb(sock, authokResp, sizeof(authokResp));
	}
	char authFailResp[2] = { AUTH_VERSION, Socks5UserPassAuth::AuthFail };
	sendallb(sock, authFailResp, sizeof(authFailResp));
	return false;
}

bool SocksProxyServer::socks5GetUserPassStr(SOCKET sock, std::string& value)
{
	unsigned char size;
	char buf[256] = { 0 };
	if (!recvallb(sock, (char*)&size, sizeof(size)))
	{
		return false;
	}
	if (!recvallb(sock, &buf[0], size))
	{
		return false;
	}
	value = std::string(buf);
	return true;
}

bool SocksProxyServer::socks5SendClientResponse(SOCKET sock, Socks5ClientResponse reply, Socks5AddressType addrType, IpAddr* ipAddr, std::string* domain, unsigned short int port)
{
	char response[4] = { (char)SocksVersion::Socks5, reply, 0, (char)addrType };
	if (!sendallb(sock, &response[0], sizeof(response)))
	{
		return false;
	}
	if (addrType == Socks5AddressType::AddrTypeIPv4 )
	{
		in_addr addr = ipAddr->get_ipv4_addr();
		if (!sendallb(sock, (char*)&addr, sizeof(addr)))
		{
			return false;
		}
	}
	else if (addrType == Socks5AddressType::AddrTypeIPv6)
	{
		in6_addr addr = ipAddr->get_addr();
		if (!sendallb(sock, (char*)&addr, sizeof(addr)))
		{
			return false;
		}
	}
	else if (addrType == Socks5AddressType::AddrTypeDomainName)
	{
		unsigned char len = domain->length();
		if (!sendallb(sock, (char*)&len, sizeof(len)))
		{
			return false;
		}
		if (!sendallb(sock, domain->c_str(), len))
		{
			return false;
		}
	}

	if (!sendallb(sock, (char*)&port, sizeof(port)))
	{
		return false;
	}
	return true;
}

bool SocksProxyServer::socks4aIsInvalidIpv4(int ip)
{
	char* rawIp = (char*)&ip;
	return (rawIp[0] == 0 && rawIp[1] == 0 && rawIp[2] == 0 && rawIp[3] != 0);
}

bool SocksProxyServer::socks4aSendClientResponse(SOCKET sock, Socks4aClientResponse status)
{
	/*
	+----+----+----+----+----+----+----+----+
	| VN | CD | DSTPORT |      DSTIP        |
	+----+----+----+----+----+----+----+----+
	 # of bytes:	   1    1      2              4

	VN is the version of the reply code and should be 0. CD is the result
	code with one of the following values:

	90: request granted
	91: request rejected or failed
	92: request rejected becasue SOCKS server cannot connect to
	    identd on the client
	93: request rejected because the client program and identd
	    report different user-ids
		*/
	char resp[8] = { 0x00, (char)status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	return sendallb(sock, resp, sizeof(resp));
}

SOCKET SocksProxyServer::socksConnect(IpAddr& ip, int port)
{
	int off = 0;
	SOCKET sock;
	struct sockaddr_in6 destAddr;
	ZeroMemory(&destAddr, sizeof(destAddr));
	destAddr.sin6_family = AF_INET6;
	destAddr.sin6_addr = ip.get_addr();
	destAddr.sin6_port = htons(port);

	info("%s: Setting up client connection to %s:%d", selfDescStr.c_str(), ip.to_string().c_str(), port);
	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		error("%s: failed to create socket (%d)", selfDescStr.c_str(), WSAGetLastError());
		goto failure;
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
	{
		error("%s: failed to set connect socket dual-stack (%d)", selfDescStr.c_str(), GetLastError());
		goto failure;
	}
	if (connect(sock, (struct sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
	{
		error("%s: failed to connect socket (%d)", selfDescStr.c_str(), WSAGetLastError());
	}
	return sock;

failure:
	closesocket(sock);
	return INVALID_SOCKET;
}

SOCKET SocksProxyServer::socksConnect(std::string domain, int port)
{
	SOCKET sock;
	char portStr[6];
	struct addrinfo* res = NULL;
	IpAddr ipAddr;

	info("%s: Setting up client connection to %s:%d", selfDescStr.c_str(), domain.c_str(), port);
	snprintf(portStr, sizeof(portStr), "%d", port);
	int ret = getaddrinfo((char*)domain.c_str(), portStr, NULL, &res);
	if (ret == EAI_NODATA)
	{
		return INVALID_SOCKET;
	}
	else if (ret == 0)
	{
		struct addrinfo* r;
		for (r = res; r != NULL; r = r->ai_next)
		{
			if (r->ai_family == AF_INET)
			{
				ipAddr = IpAddr(((sockaddr_in*)r->ai_addr)->sin_addr);
				sock = this->socksConnect(ipAddr, port);
			}
			else if (r->ai_family == AF_INET6)
			{
				ipAddr = IpAddr(((sockaddr_in6*)r->ai_addr)->sin6_addr);
				sock = this->socksConnect(ipAddr, port);
			}
			
			if (sock != INVALID_SOCKET)
			{
				break;
			}			
		}
	}

	if (res != NULL)
	{
		freeaddrinfo(res);
		res = NULL;
	}
	return sock;
}

void SocksProxyServer::ProxyConnectionWorker(SocksServerConnectionData* data)
{
	SOCKET sock = data->clientSocket;
	sockaddr_in6 clientAddr = data->clientAddr;
	delete data;
	data = NULL;
	SOCKET proxySock = INVALID_SOCKET;

	SocksVersion version = this->recvSocksVersion(sock);
	info("SOCKS version: %d", version);
	switch (version)
	{
	case SocksVersion::Socks4:
	{
		if (this->enableSocks4)
		{
			proxySock = this->ProcessSocks4Connection(sock);
		}	
		else
		{
			warning("Received unsupported SOCKS connection");
		}
	}
	break;
	case SocksVersion::Socks5:
	{
		if (this->enableSocks5)
		{
			proxySock = this->ProcessSocks5Connection(sock);
		}
		else
		{
			warning("Received unsupported SOCKS connection");
		}
	}
	break;
	}
	if (proxySock != INVALID_SOCKET)
	{
		sockaddr_in6 proxySockAddr;
		int proxySockAddrLen = sizeof(proxySockAddr);
		if (getsockname(proxySock, (struct sockaddr*)&proxySockAddr, &proxySockAddrLen) == -1)
		{
			error("%s: failed to get bind socket port (%d)", this->selfDescStr.c_str(), WSAGetLastError());
			goto failure;
		}
		

		ProxyTunnelWorkerData* tunnelDataA = new ProxyTunnelWorkerData();
		ProxyTunnelWorkerData* tunnelDataB = new ProxyTunnelWorkerData();
		tunnelDataA->sockA = sock;
		tunnelDataA->sockAAddr = IpAddr(clientAddr.sin6_addr);
		tunnelDataA->sockAPort = ntohs(clientAddr.sin6_port);
		tunnelDataA->sockB = proxySock;
		tunnelDataA->sockBAddr = IpAddr(proxySockAddr.sin6_addr);
		tunnelDataA->sockBPort = ntohs(proxySockAddr.sin6_port);

		tunnelDataB->sockA = proxySock;
		tunnelDataB->sockAAddr = tunnelDataA->sockBAddr;
		tunnelDataB->sockAPort = tunnelDataA->sockBPort;
		tunnelDataB->sockB = sock;
		tunnelDataB->sockBAddr = tunnelDataA->sockAAddr;
		tunnelDataB->sockBPort = tunnelDataA->sockAPort;
		std::thread tunnelThread(&ProxyTunnelWorker, tunnelDataA, this->selfDescStr);
		ProxyTunnelWorker(tunnelDataB, this->selfDescStr);
		tunnelThread.join();
	}

failure:
	closesocket(sock);
	closesocket(proxySock);
}

SocksVersion SocksProxyServer::recvSocksVersion(SOCKET sock)
{
	char buf;
	int bufLen = sizeof(buf);
	recvall(sock, (char*)&buf, bufLen);
	return (SocksVersion)buf;
}

bool SocksProxyServer::Start()
{
	int on = 1;
	int off = 0;
	WSADATA wsa_data;
	WORD wsa_version = MAKEWORD(2, 2);
	struct sockaddr_in6 addr;
	info("%s: Start", this->selfDescStr.c_str());

	if (WSAStartup(wsa_version, &wsa_data) != 0)
	{
		error("%s: failed to start WSA (%d)", this->selfDescStr.c_str(), GetLastError());
		goto failure;
	}
	this->serverSock = socket(AF_INET6, SOCK_STREAM, 0);
	if (this->serverSock == INVALID_SOCKET)
	{
		error("%s: failed to create socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
		goto failure;
	}
	if (WSAStartup(wsa_version, &wsa_data) != 0)
	{
		error("%s: failed to start WSA (%d)", this->selfDescStr.c_str(), GetLastError());
		goto failure;
	}
	if (setsockopt(this->serverSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int)) == SOCKET_ERROR)
	{
		error("%s: failed to re-use address (%d)", this->selfDescStr.c_str(), GetLastError());
		goto failure;
	}
	if (setsockopt(this->serverSock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
	{
		error("%s: failed to set socket dual-stack (%d)", this->selfDescStr.c_str(), GetLastError());
		goto failure;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(this->port);
	addr.sin6_addr = in6addr_any;

	if (::bind(this->serverSock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		error("%s: failed to bind socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
		goto failure;
	}

	if (this->port == 0)
	{
		struct sockaddr_in6 bind_addr;
		int bind_addr_len = sizeof(bind_addr);
		if (getsockname(this->serverSock, (struct sockaddr*)&bind_addr, &bind_addr_len) == -1)
		{
			error("%s: failed to get bind socket port (%d)", this->selfDescStr.c_str(), WSAGetLastError());
		}
		this->port = ntohs(bind_addr.sin6_port);
	}

	if (listen(this->serverSock, 25) == SOCKET_ERROR)
	{
		error("%s: failed to listen socket (%d)", this->selfDescStr.c_str(), WSAGetLastError());
		goto failure;
	}

	this->selfDescStr = this->getSelfDescription();
	this->serverThread = std::thread(&SocksProxyServer::ProxyServerWorker, this);
	this->running = true;
	info("%s: Start completed", this->selfDescStr.c_str());
	return true;

failure:
	error("%s: Start failed", this->selfDescStr.c_str());
	this->Stop();
	return false;
}

bool SocksProxyServer::Stop()
{
	return false;
}
