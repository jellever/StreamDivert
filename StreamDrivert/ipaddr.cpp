#include "stdafx.h"
#include "ipaddr.h"
#include <cstring>
#include <ws2tcpip.h>
#include "utils.h"


void IpAddr::initIpv4(const in_addr & addr)
{
	memcpy(&this->m_addr.s6_addr[0], ipv4_mapped_prefix, sizeof(ipv4_mapped_prefix));
	memcpy(&this->m_addr.s6_addr[12], &addr.s_addr, sizeof(addr));
}

void IpAddr::initIpv6(const in6_addr & addr)
{
	this->m_addr = addr;
}

IpAddr::IpAddr()
{
	memset(&this->m_addr, 0, sizeof(in6_addr));
}

IpAddr::IpAddr(const in_addr& addr)
{
	this->initIpv4(addr);
}

IpAddr::IpAddr(const in6_addr& addr)
{
	this->initIpv6(addr);
}

IpAddr::IpAddr(const std::string & addrstr)
{
	struct in_addr addr;
	bool isipv4 = inet_pton(AF_INET, addrstr.c_str(), &addr) != 0;
	if (isipv4)
	{
		this->initIpv4(addr);
	}
	struct in6_addr addr6;
	bool isipv6 = inet_pton(AF_INET6, addrstr.c_str(), &addr6) != 0;
	if (isipv6)
	{
		this->initIpv6(addr6);
	}
}

IpAddr::~IpAddr()
{
}

IPFamily IpAddr::get_family()
{
	if(memcmp(&this->m_addr.s6_addr[0], ipv4_mapped_prefix, sizeof(ipv4_mapped_prefix)) == 0)
	{
		return IPFamily::IPv4;
	}
	else
	{
		return IPFamily::IPv6;
	}
}

std::string IpAddr::to_string()
{
	std::string result;

	IPFamily ipfamily = this->get_family();
	if(ipfamily == IPFamily::IPv4)
	{
		result.resize(INET_ADDRSTRLEN);		
		const char* r = inet_ntop(AF_INET, &this->m_addr.s6_addr[12], &result[0], INET_ADDRSTRLEN);
		if (r == NULL)
		{
			error("Failed to convert ip to ipv4 address string!");
		}
	}
	else if(ipfamily == IPFamily::IPv6)
	{
		result.resize(INET6_ADDRSTRLEN);		
		const char* r = inet_ntop(AF_INET6, &this->m_addr, &result[0], INET6_ADDRSTRLEN);
		if (r == NULL)
		{
			error("Failed to convert ip to ipv6 address string!");
		}
	}
	result.resize(strlen(result.c_str()));
	return result;
}

in6_addr IpAddr::get_addr()
{
	return this->m_addr;
}

in_addr IpAddr::get_ipv4_addr()
{
	return *(in_addr*)&this->m_addr.s6_addr[12];
}

bool IpAddr::operator==(const IpAddr& addr2)
{
	return memcmp(&this->m_addr, &addr2.m_addr, sizeof(in6_addr)) == 0;
}

bool IpAddr::operator==(const UINT32 & addr2)
{
	if (this->get_family() != IPFamily::IPv4)
	{
		return false;
	}
	return memcmp(&this->m_addr.s6_addr[12], &addr2, sizeof(in_addr)) == 0;
}

bool IpAddr::operator!=(const IpAddr& addr2)
{
	return ! (*this == addr2);
}

bool IpAddr::operator<(const IpAddr& addr2)
{
	return memcmp(&this->m_addr, &addr2.m_addr, sizeof(in6_addr)) < 0;
}

bool IpAddr::operator<=(const IpAddr& addr2)
{
	return *this < addr2 || *this == addr2;
}

bool IpAddr::operator>=(const IpAddr& addr2)
{
	return ! ( *this < addr2 );
}

bool IpAddr::operator>(const IpAddr& addr2)
{
	return ! ( *this <= addr2 );
}