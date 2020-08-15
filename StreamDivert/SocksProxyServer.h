#pragma once
#include <winsock2.h>
#include <thread>
#include <mutex>
#include "ipaddr.h"

struct SocksServerConnectionData
{
	SOCKET clientSocket;
	sockaddr_in6 clientAddr;
};

enum SocksVersion
{
	SocksVerNone = 0x0,
	Socks4 = 0x04,
	Socks5 = 0x05,
};



enum Socks4aClientResponse : char
{
	RequestGranted = 90,
	RequestRejectedOrFailed = 91,
	RequestRejectedIdentd = 92,
	RequestRejectedUserid = 93
};

enum Socks5ClientResponse : char
{
	succeeded = 0,
	GeneralServerFailure = 1,
	ConnectionNotAllowed = 2,
	NetworkUnreachable = 3,
	HostUnreachable = 4,
	ConnectionRefused = 5,
	TTLExpired = 6,
	CommandNotSupported = 7,
	AddressTypeNotSupported = 8
};

enum Socks5AuthMethods {
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

enum Socks5UserPassAuth
{
	AuthOk = 0,
	AuthFail = 0xff
};

enum Socks5AddressType
{
	AddrTypeNone = 0,
	AddrTypeIPv4 = 1,
	AddrTypeDomainName = 3,
	AddrTypeIPv6 = 4
};

#define CMD_CONNECT 0x1
#define AUTH_VERSION 0x1

class SocksProxyServer
{
protected:
	int port;
	SOCKET serverSock;
	std::thread serverThread;
	std::string selfDescStr;
	std::recursive_mutex resourceLock;
	bool running;
	Socks5AuthMethods socks5AuthType;
	std::string username;
	std::string password;
	bool enableSocks4;
	bool enableSocks5;

	std::string getSelfDescription();
	void ProxyServerWorker();
	void ProxyConnectionWorker(SocksServerConnectionData* data);
	SocksVersion recvSocksVersion(SOCKET sock);
	SOCKET ProcessSocks4Connection(SOCKET sock);
	bool socks4aIsInvalidIpv4(int ip);
	bool socks4aSendClientResponse(SOCKET sock, Socks4aClientResponse response);
	SOCKET ProcessSocks5Connection(SOCKET sock);
	bool socks5Auth(SOCKET sock, int methods);
	void socks5SendAuthNotSupported(SOCKET sock);
	void socks5SendNoAth(SOCKET sock);
	bool socks5UserPassAuthentication(SOCKET sock);
	bool socks5GetUserPassStr(SOCKET sock, std::string& user);
	bool socks5SendClientResponse(SOCKET sock, Socks5ClientResponse reply, Socks5AddressType addrType, IpAddr* ipAddr, std::string* domain, unsigned short int port);
	SOCKET socksConnect(IpAddr& ip, int port);
	SOCKET socksConnect(std::string domain, int port);
public:
	SocksProxyServer(int port, bool enableSocks4, bool enableSocks5);
	SocksProxyServer(int port);

	~SocksProxyServer();
	void SetAuthType(Socks5AuthMethods method);
	void SetAuthUsername(std::string& username);
	void SetAuthPassword(std::string& password);
	bool Start();
	bool Stop();
};

