#pragma once
#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
#include <string>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


class WindowsFirewall
{
protected:
	INetFwProfile* profile;
	
public:
	WindowsFirewall();
	~WindowsFirewall();
	bool Initialize();
	bool IsFirewallOn(bool& on);
	bool PortIsConfigured(long port, NET_FW_IP_PROTOCOL proto, bool& isConfigured);
	bool AddPort(long port, NET_FW_IP_PROTOCOL ipProtocol, std::string& name);
	bool RemovePort(long port, NET_FW_IP_PROTOCOL ipProtocol);
	bool IsApplicationConfigured(std::string path, bool& configured);
	bool AddApplication(std::string path, std::string name);
	bool RemoveApplication(std::string path);
};

