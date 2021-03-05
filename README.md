# StreamDivert
StreamDivert is a tool to man-in-the-middle or relay in and outgoing network connections on a system. It has the ability to, for example, relay all incoming SMB connections to port 445 to another server, or only relay specific incoming SMB connections from a specific set of source IP's to another server. Summed up, StreamDivert is able to:


*  Relay all incoming connections to a specific port to another destination.
*  Relay incoming connections from a specific source IP to a port to another destination.
*  Relay incoming connections to a SOCKS(4/5) server.
*  Relay all outgoing connections to a specific port to another destination.
*  Relay outgoing connections to a specific IP and port to another destination.
*  Handle TCP, UDP and ICMP traffic over IPv4 and IPv6.
*  Force redirected packets over a specific network interface.

## Download Binaries
Pre-compiled binaries for StreamDivert can be downloaded [here](https://github.com/jellever/StreamDivert/releases).

## Usage
How do you use StreamDivert? Run the the tool with administrative privileges:

```console
streamdivert.exe config_file [-f]
```

The config file contains entries for streams you want to have diverted. En example config file:
```conf
//Divert all inbound TCP connections to port 445 (SMB) coming from 10.0.1.50 to 10.0.1.49 port 445
tcp < 445 10.0.1.50 -> 10.0.1.49 445

//Divert all inbound TCP connections to port 445 (SMB) coming from 10.0.1.51 to a local SOCKS server
tcp < 445 10.0.1.51 -> socks

//Divert all inbound TCP connections to port 445 (SMB) coming from fe80::f477:846a:775d:d37 to fe80::20c:29ff:fe6f:88ff port 445
tcp < 445 fe80::f477:846a:775d:d37 -> fe80::20c:29ff:fe6f:88ff 445

//Divert all inbound TCP connections to port 445 (SMB) to 10.0.1.48 port 445
tcp < 445 0.0.0.0 -> 10.0.1.48 445

//Divert all inbound UDP connections to to port 53 (DNS) to  10.0.1.49 port 53
udp < 53 0.0.0.0 -> 10.0.1.49 53

//Divert all inbound ICMP packets coming from 10.0.1.50 to 10.0.1.49
icmp < 10.0.1.50 -> 10.0.1.49

//Divert all outbound TCP connections to 10.0.1.50, port 80 to 10.0.1.49 port 8080
tcp > 10.0.1.50 80 -> 10.0.1.49 8080

//Send all packets going to 10.0.1.50 port 80 and prefer interface 9 to send them. If the interface does not exist or is not up, the packets are send from the default interface.
tcp > 10.0.1.50 80 -> 10.0.1.50 80 interface 9

//Force all packets going to 10.0.1.50 port 80 over interface 9, or drop the packets if the interface does not exist or is not up.
tcp > 10.0.1.50 80 -> 10.0.1.50 80 force interface 9

//Divert all outbound UDP connection to port 53 (DNS) to 10.0.1.49 port 53
udp > 0.0.0.0 53 -> 10.0.1.49 53
```

The [-f] flag, when present, will modify the Windows Firewall to add an exception for the application to properly redirect incoming traffic to another port.

## Some Use Cases
*  Diverting outbound C&C traffic to a local socket for dynamic malware analysis.
*  Diverting inbound SMB connections of a compromised host to Responder/ ntlmrelayx (usefull in penetration tests).
*  Routing traffic over reserved ports. Usefull when a network firewall is in between. For example...
    *  Routing a meterpreter shell over port 445.
    *  Running a SOCKS server on port 3389.
*  ...

## Help! My packets/ connections are not correctly diverted!
One thing to keep in mind when configuring diverted connections is that you don't have conflicting diverted streams. Given the following example config file:
```conf
icmp < 0.0.0.0 -> 10.0.1.50
icmp > 10.0.1.49 -> 10.0.1.48
```
Those two diverted streams will conflict with eachother, as packets for the first diverted stream will also be picked up by the second packet 'diverter'. Generally you will only run into these issues with UDP and ICMP and using wildcards. 

Also note that diverting an IPv4 to an IPv6 address and vice versa is not supported for UDP and ICMP traffic.
## Contributing to StreamDivert
Features wanted:
*  IP range support
*  ...
