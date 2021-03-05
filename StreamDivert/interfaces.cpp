#include "stdafx.h"
#include "interfaces.h"


// Link with Iphlpapi.lib
#pragma comment(lib, "IPHLPAPI.lib")


std::string InterfaceTypeToFriendName(int ifType)
{
    switch (ifType)
    {
    case 1:
        return "Other";
    case 6:
        return "Ethernet";
    case 9:
        return "Token ring";
    case 23:
        return "PPP";
    case 24:
        return "Software loopback";
    case 37:
        return "ATM";
    case 71:
        return "Wiress";
    case 131:
        return "Tunnel";
    case 144:
        return "IEEE 1394 serial bus";
    }
    return "Unknown";
}

void PrintInterfaceInfo()
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    unsigned int i = 0;

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    // default to unspecified address family (both)
    ULONG family = AF_UNSPEC;

    LPVOID lpMsgBuf = NULL;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
    PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
    IP_ADAPTER_DNS_SERVER_ADDRESS* pDnServer = NULL;
    IP_ADAPTER_PREFIX* pPrefix = NULL;

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;

    do {

        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            printf
            ("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
            exit(1);
        }

        dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        }
        else {
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            //printf("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n",  pCurrAddresses->Length);
            printf("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
            //printf("\tAdapter name: %s\n", pCurrAddresses->AdapterName);

            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if (pUnicast != NULL) {
                for (i = 0; pUnicast != NULL; i++)
                    pUnicast = pUnicast->Next;
               // printf("\tNumber of Unicast Addresses: %d\n", i);
            }
           // else
               // printf("\tNo Unicast Addresses\n");

            pAnycast = pCurrAddresses->FirstAnycastAddress;
            if (pAnycast) {
                for (i = 0; pAnycast != NULL; i++)
                    pAnycast = pAnycast->Next;
                //printf("\tNumber of Anycast Addresses: %d\n", i);
            }
            //else
                //printf("\tNo Anycast Addresses\n");

            pMulticast = pCurrAddresses->FirstMulticastAddress;
            if (pMulticast) {
                for (i = 0; pMulticast != NULL; i++)
                    pMulticast = pMulticast->Next;
               // printf("\tNumber of Multicast Addresses: %d\n", i);
            }
            //else
               // printf("\tNo Multicast Addresses\n");

            pDnServer = pCurrAddresses->FirstDnsServerAddress;
            if (pDnServer) {
                for (i = 0; pDnServer != NULL; i++)
                    pDnServer = pDnServer->Next;
                //printf("\tNumber of DNS Server Addresses: %d\n", i);
            }
            else
                printf("\tNo DNS Server Addresses\n");

            printf("\tDNS Suffix: %wS\n", pCurrAddresses->DnsSuffix);
            printf("\tDescription: %wS\n", pCurrAddresses->Description);
            printf("\tFriendly name: %wS\n", pCurrAddresses->FriendlyName);

            if (pCurrAddresses->PhysicalAddressLength != 0) {
                printf("\tPhysical address: ");
                for (i = 0; i < (int)pCurrAddresses->PhysicalAddressLength;
                    i++) {
                    if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                        printf("%.2X\n",
                            (int)pCurrAddresses->PhysicalAddress[i]);
                    else
                        printf("%.2X-",
                            (int)pCurrAddresses->PhysicalAddress[i]);
                }
            }
            //printf("\tFlags: %ld\n", pCurrAddresses->Flags);
            printf("\tMtu: %lu\n", pCurrAddresses->Mtu);
            printf("\tIfType: %s\n", InterfaceTypeToFriendName(pCurrAddresses->IfType).c_str());
            printf("\tOperStatus: %ld\n", pCurrAddresses->OperStatus);
            printf("\tIpv6IfIndex (IPv6 interface): %u\n",
                pCurrAddresses->Ipv6IfIndex);
            //printf("\tZoneIndices (hex): ");
            //for (i = 0; i < 16; i++)
             //   printf("%lx ", pCurrAddresses->ZoneIndices[i]);
            printf("\n");

            //printf("\tTransmit link speed: %I64u\n", pCurrAddresses->TransmitLinkSpeed);
            //printf("\tReceive link speed: %I64u\n", pCurrAddresses->ReceiveLinkSpeed);

            pPrefix = pCurrAddresses->FirstPrefix;
            if (pPrefix) {
                for (i = 0; pPrefix != NULL; i++)
                    pPrefix = pPrefix->Next;
               // printf("\tNumber of IP Adapter Prefix entries: %d\n", i);
            }
            //else
                //printf("\tNumber of IP Adapter Prefix entries: 0\n");

           

            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    else {
        printf("Call to GetAdaptersAddresses failed with error: %d\n",
            dwRetVal);
        if (dwRetVal == ERROR_NO_DATA)
            printf("\tNo addresses were found for the requested parameters\n");
        else {

            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                // Default language
                (LPTSTR)&lpMsgBuf, 0, NULL)) {
                printf("\tError: %s", lpMsgBuf);
                LocalFree(lpMsgBuf);
                if (pAddresses)
                    free(pAddresses);
                exit(1);
            }
        }
    }

    if (pAddresses) {
        free(pAddresses);
    }
}


bool GetInterfaceAddressByIdx(UINT16 ifIdx, IpAddr& addr, IPFamily family, bool onlyEnabled)
{  
    DWORD flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST;
    ULONG wantedFamily = AF_UNSPEC;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG iterations = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    DWORD dwRetVal = 0;
    DWORD dwSize = 0;
    unsigned int i = 0;
    bool result = false;

    outBufLen = WORKING_BUFFER_SIZE;
    do {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            return false;
        }

        dwRetVal = GetAdaptersAddresses(wantedFamily, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        }
        else {
            break;
        }
        iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->IfIndex == ifIdx && (onlyEnabled && pCurrAddresses->OperStatus == IfOperStatusUp))
            {
                //pCurrAddresses->
                pUnicast = pCurrAddresses->FirstUnicastAddress;
                if (pUnicast)
                {
                    for (i = 0; pUnicast != NULL; i++)
                    {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6 && (family == IPFamily::IPv6 || family == IPFamily::Unknown))
                        {
                            addr = IpAddr(((sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr);
                            result = true;
                            goto CLEANUP;
                        }
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET && (family == IPFamily::IPv4 || family == IPFamily::Unknown))
                        {
                            addr = IpAddr(((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr);
                            result = true;
                            goto CLEANUP;
                        }
                        pUnicast = pUnicast->Next;
                    }
                }
            }

            pCurrAddresses = pCurrAddresses->Next;
        }
    }

CLEANUP:
    if (pAddresses) {
        free(pAddresses);
    }
    return result;
}