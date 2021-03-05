#pragma once
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "ipaddr.h"


#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3



void PrintInterfaceInfo();
bool GetInterfaceAddressByIdx(UINT16 ifIdx, IpAddr& addr, IPFamily family, bool onlyEnabled);