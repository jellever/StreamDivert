#pragma once
#include <string>
#include <winsock2.h>
#include <Ws2ipdef.h>

enum IPFamily : int
{ 
	Unknown = -1,
	IPv4 = 4, 
	IPv6 = 6, 
};


const uint8_t ipv4_mapped_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

class IpAddr
{
protected:
	in6_addr m_addr;
#if _DEBUG
	std::string addrStr;
#endif
	void initIpv4(const in_addr& addr);
	void initIpv6(const in6_addr& addr);
	void init();

public:
	IpAddr();
	IpAddr(const in_addr& addr);
	IpAddr(const in6_addr& addr);
	IpAddr(const std::string& addr);
	~IpAddr();
	bool operator==(const IpAddr& addr2);
	bool operator==(const UINT32& addr2);
	bool operator!=(const IpAddr& addr2);
	bool operator<(const IpAddr& addr2);
	bool operator<=(const IpAddr& addr2);
	bool operator>=(const IpAddr& addr2);
	bool operator>(const IpAddr& addr2);
	IPFamily get_family();
	std::string to_string();
	in6_addr get_addr();
	in_addr get_ipv4_addr();
};
