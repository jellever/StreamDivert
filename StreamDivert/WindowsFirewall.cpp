#include "stdafx.h"
#include "WindowsFirewall.h"
#include "utils.h"

WindowsFirewall::WindowsFirewall()
{
    this->profile = NULL;
}

WindowsFirewall::~WindowsFirewall()
{
    // Release the firewall profile.
    if (this->profile != NULL)
    {
        this->profile->Release();
        this->profile = NULL;
    }
}

bool WindowsFirewall::Initialize()
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    CoInitialize(NULL);

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance(
        __uuidof(NetFwMgr),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwMgr),
        (void**)&fwMgr
    );
    if (FAILED(hr))
    {
        error("CoCreateInstance failed: 0x%08lx\n", hr);
        goto error;
    }


    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
        error("get_LocalPolicy failed: 0x%08lx\n", hr);
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(&this->profile);
    if (FAILED(hr))
    {
        error("get_CurrentProfile failed: 0x%08lx\n", hr);
        goto error;
    }

error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return SUCCEEDED(hr);   
}

bool WindowsFirewall::IsFirewallOn(bool& fwOn)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;
    fwOn = FALSE;

    // Get the current state of the firewall.
    hr = this->profile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
        error("get_FirewallEnabled failed: 0x%08lx\n", hr);
        goto error;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
    {
        fwOn = TRUE;       
    }   

error:
    return SUCCEEDED(hr);
}

bool WindowsFirewall::PortIsConfigured(long port, NET_FW_IP_PROTOCOL proto, bool& isConfigured)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;
    INetFwOpenPort* fwOpenPort = NULL;
    INetFwOpenPorts* fwOpenPorts = NULL;

    isConfigured = FALSE;

    // Retrieve the globally open ports collection.
    hr = this->profile->get_GloballyOpenPorts(&fwOpenPorts);
    if (FAILED(hr))
    {
        error("get_GloballyOpenPorts failed: 0x%08lx\n", hr);
        goto error;
    }

    // Attempt to retrieve the globally open port.
    hr = fwOpenPorts->Item(port, proto, &fwOpenPort);
    if (SUCCEEDED(hr))
    {
        // Find out if the globally open port is enabled.
        hr = fwOpenPort->get_Enabled(&fwEnabled);
        if (FAILED(hr))
        {
            error("get_Enabled failed: 0x%08lx\n", hr);
            goto error;
        }

        if (fwEnabled != VARIANT_FALSE)
        {
            // The globally open port is enabled.
            isConfigured = TRUE;           
        }       
    }
    else
    {
        // The globally open port was not in the collection.
        hr = S_OK;       
    }

error:

    // Release the globally open port.
    if (fwOpenPort != NULL)
    {
        fwOpenPort->Release();
    }

    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
    {
        fwOpenPorts->Release();
    }

    return SUCCEEDED(hr);
}

bool WindowsFirewall::AddPort(long port, NET_FW_IP_PROTOCOL ipProtocol, std::string& name)
{
    HRESULT hr = S_OK;
    bool fwPortEnabled;
    BSTR fwBstrName = NULL;
    INetFwOpenPort* fwOpenPort = NULL;
    INetFwOpenPorts* fwOpenPorts = NULL;  

    // First check to see if the port is already added.
    if(!this->PortIsConfigured(port, ipProtocol, fwPortEnabled))    
    {
        error("PortIsConfigured failed\n");
        hr = E_FAIL;
        goto error;
    }

    // Only add the port if it isn't already added.
    if (!fwPortEnabled)
    {
        // Retrieve the collection of globally open ports.
        hr = this->profile->get_GloballyOpenPorts(&fwOpenPorts);
        if (FAILED(hr))
        {
            error("get_GloballyOpenPorts failed: 0x%08lx\n", hr);
            goto error;
        }

        // Create an instance of an open port.
        hr = CoCreateInstance(
            __uuidof(NetFwOpenPort),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwOpenPort),
            (void**)&fwOpenPort
        );
        if (FAILED(hr))
        {
            printf("CoCreateInstance failed: 0x%08lx\n", hr);
            goto error;
        }

        // Set the port number.
        hr = fwOpenPort->put_Port(port);
        if (FAILED(hr))
        {
            printf("put_Port failed: 0x%08lx\n", hr);
            goto error;
        }

        // Set the IP protocol.
        hr = fwOpenPort->put_Protocol(ipProtocol);
        if (FAILED(hr))
        {
            printf("put_Protocol failed: 0x%08lx\n", hr);
            goto error;
        }

        // Allocate a BSTR for the friendly name of the port.
        int wslen = MultiByteToWideChar(CP_ACP, 0, name.c_str(), name.length(), 0, 0);
        fwBstrName = SysAllocStringLen(0, wslen);
        MultiByteToWideChar(CP_ACP, 0, name.c_str(), name.length(), fwBstrName, wslen);
        if (SysStringLen(fwBstrName) == 0)
        {
            hr = E_OUTOFMEMORY;
            error("SysAllocString failed: 0x%08lx\n", hr);
            goto error;
        }

        // Set the friendly name of the port.
        hr = fwOpenPort->put_Name(fwBstrName);
        if (FAILED(hr))
        {
            error("put_Name failed: 0x%08lx\n", hr);
            goto error;
        }

        // Opens the port and adds it to the collection.
        hr = fwOpenPorts->Add(fwOpenPort);
        if (FAILED(hr))
        {
            error("Add failed: 0x%08lx\n", hr);
            goto error;
        }

        info("Port %ld is now open in the firewall.\n", port);
    }

error:

    // Free the BSTR.
    SysFreeString(fwBstrName);

    // Release the open port instance.
    if (fwOpenPort != NULL)
    {
        fwOpenPort->Release();
    }

    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
    {
        fwOpenPorts->Release();
    }

    return SUCCEEDED(hr);
}

bool WindowsFirewall::RemovePort(long port, NET_FW_IP_PROTOCOL ipProtocol)
{
    HRESULT hr = S_OK;
    bool fwPortEnabled;   
    INetFwOpenPorts* fwOpenPorts = NULL;

    // First check to see if the port is already added.
    if (!this->PortIsConfigured(port, ipProtocol, fwPortEnabled))
    {
        error("PortIsConfigured failed\n");
        hr = E_FAIL;
        goto error;
    }

    // Only add the port if it isn't already added.
    if (fwPortEnabled)
    {
        // Retrieve the collection of globally open ports.
        hr = this->profile->get_GloballyOpenPorts(&fwOpenPorts);
        if (FAILED(hr))
        {
            error("get_GloballyOpenPorts failed: 0x%08lx\n", hr);
            goto error;
        }

        hr = fwOpenPorts->Remove(port, ipProtocol);
        if (FAILED(hr))
        {
            error("Remove failed: 0x%08lx\n", hr);
            goto error;
        }
    }

error:
    
    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
    {
        fwOpenPorts->Release();
    }

    return SUCCEEDED(hr);
}

bool WindowsFirewall::IsApplicationConfigured(std::string path, bool& configured)
{
    HRESULT hr = S_OK;
    BSTR fwBstrProcessImageFileName = NULL;
    VARIANT_BOOL fwEnabled;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;       

    configured = FALSE;

    // Retrieve the authorized application collection.
    hr = this->profile->get_AuthorizedApplications(&fwApps);
    if (FAILED(hr))
    {
        error("get_AuthorizedApplications failed: 0x%08lx\n", hr);
        goto error;
    }

    // Allocate a BSTR for the process image file name.
    int wslen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), 0, 0);
    fwBstrProcessImageFileName = SysAllocStringLen(0, wslen);   
    if (fwBstrProcessImageFileName == NULL)
    {
        hr = E_OUTOFMEMORY;
        error("SysAllocString failed: 0x%08lx\n", hr);
        goto error;
    }
    MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), fwBstrProcessImageFileName, wslen);

    // Attempt to retrieve the authorized application.
    hr = fwApps->Item(fwBstrProcessImageFileName, &fwApp);
    if (SUCCEEDED(hr))
    {
        // Find out if the authorized application is enabled.
        hr = fwApp->get_Enabled(&fwEnabled);
        if (FAILED(hr))
        {
            error("get_Enabled failed: 0x%08lx\n", hr);
            goto error;
        }

        if (fwEnabled != VARIANT_FALSE)
        {
            // The authorized application is enabled.
            configured = TRUE;
        }
    }
    else
    {
        // The authorized application was not in the collection.
        hr = S_OK;      
    }

error:

    // Free the BSTR.
    SysFreeString(fwBstrProcessImageFileName);
    // Release the authorized application instance.
    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    // Release the authorized application collection.
    if (fwApps != NULL)
    {
        fwApps->Release();
    }
    return SUCCEEDED(hr);
}

bool WindowsFirewall::AddApplication(std::string path, std::string name)
{
    HRESULT hr = S_OK;
    bool fwAppEnabled;
    BSTR fwBstrName = NULL;
    BSTR fwBstrProcessImageFileName = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;   

    // First check to see if the application is already authorized.    
    if (!IsApplicationConfigured(path, fwAppEnabled))
    {
        printf("WindowsFirewallAppIsEnabled failed: 0x%08lx\n", hr);
        goto error;
    }

    // Only add the application if it isn't already authorized.
    if (!fwAppEnabled)
    {
        // Retrieve the authorized application collection.
        hr = this->profile->get_AuthorizedApplications(&fwApps);
        if (FAILED(hr))
        {
            printf("get_AuthorizedApplications failed: 0x%08lx\n", hr);
            goto error;
        }

        // Create an instance of an authorized application.
        hr = CoCreateInstance(
            __uuidof(NetFwAuthorizedApplication),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwAuthorizedApplication),
            (void**)&fwApp
        );
        if (FAILED(hr))
        {
            printf("CoCreateInstance failed: 0x%08lx\n", hr);
            goto error;
        }

        // Allocate a BSTR for the process image file name.
        int wslen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), 0, 0);
        fwBstrProcessImageFileName = SysAllocStringLen(0, wslen);
        if (fwBstrProcessImageFileName == NULL)
        {
            hr = E_OUTOFMEMORY;
            printf("SysAllocString failed: 0x%08lx\n", hr);
            goto error;
        }
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), fwBstrProcessImageFileName, wslen);

        // Set the process image file name.
        hr = fwApp->put_ProcessImageFileName(fwBstrProcessImageFileName);
        if (FAILED(hr))
        {
            printf("put_ProcessImageFileName failed: 0x%08lx\n", hr);
            goto error;
        }

        // Allocate a BSTR for the application friendly name.
        wslen = MultiByteToWideChar(CP_ACP, 0, name.c_str(), name.length(), 0, 0);
        fwBstrName = SysAllocStringLen(0, wslen);        
        if (SysStringLen(fwBstrName) == 0)
        {
            hr = E_OUTOFMEMORY;
            printf("SysAllocString failed: 0x%08lx\n", hr);
            goto error;
        }
        MultiByteToWideChar(CP_ACP, 0, name.c_str(), name.length(), fwBstrName, wslen);

        // Set the application friendly name.
        hr = fwApp->put_Name(fwBstrName);
        if (FAILED(hr))
        {
            printf("put_Name failed: 0x%08lx\n", hr);
            goto error;
        }

        // Add the application to the collection.
        hr = fwApps->Add(fwApp);
        if (FAILED(hr))
        {
            printf("Add failed: 0x%08lx\n", hr);
            goto error;
        }

        info("Authorized application %s is now enabled in the firewall.\n", path.c_str());
    }
    else
    {
        info("Authorized application %s is already enabled in the firewall.\n", path.c_str());
    }

error:

    // Free the BSTRs.
    SysFreeString(fwBstrName);
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    // Release the authorized application collection.
    if (fwApps != NULL)
    {
        fwApps->Release();
    }

    return SUCCEEDED(hr);
}

bool WindowsFirewall::RemoveApplication(std::string path)
{
    HRESULT hr = S_OK;
    bool fwAppEnabled;
    BSTR fwBstrName = NULL;
    BSTR fwBstrProcessImageFileName = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;

    // First check to see if the application is already authorized.    
    if (!IsApplicationConfigured(path, fwAppEnabled))
    {
        printf("WindowsFirewallAppIsEnabled failed: 0x%08lx\n", hr);
        goto error;
    }

    // Only add the application if it isn't already authorized.
    if (fwAppEnabled)
    {
        // Retrieve the authorized application collection.
        hr = this->profile->get_AuthorizedApplications(&fwApps);
        if (FAILED(hr))
        {
            printf("get_AuthorizedApplications failed: 0x%08lx\n", hr);
            goto error;
        }
        
        // Allocate a BSTR for the process image file name.
        int wslen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), 0, 0);
        fwBstrProcessImageFileName = SysAllocStringLen(0, wslen);
        if (fwBstrProcessImageFileName == NULL)
        {
            hr = E_OUTOFMEMORY;
            printf("SysAllocString failed: 0x%08lx\n", hr);
            goto error;
        }
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), path.length(), fwBstrProcessImageFileName, wslen);
        
        
        hr = fwApps->Remove(fwBstrProcessImageFileName);
        if (SUCCEEDED(hr))
        {
            info("Authorized application %lS is now removed from the firewall.\n", path.c_str());
        }
    }

error:
    // Release the authorized application collection.
    if (fwApps != NULL)
    {
        fwApps->Release();
    }
    return SUCCEEDED(hr);
}
