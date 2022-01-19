# Authors

This work was made by André Flores (up201907001) and Tiago Rodrigues (up201906807).

# Summary

This project was made for the Computer Networks class of the Degree in Informatics Engineering and Computation at the Faculty of Engeneering of the University of Porto.

All objectives were completed.

# Introduction

The two main components of the project were the development of a download application that uses FTP (File Transfer Protocol) and the configuration of a network made up of 3 computers, a switch (with 2 Virtual Local Area Networks) and a router.

This report pertains to both parts of the project

# Part 1 - Download Application

Command line format:

``` bash
download ftp://[<username>:<password>@]<host>/<url-path>
```

The download application parses the username, password, host and path from the specified URL (if the username and password aren't specified the application will attempt an anonymous login). The application finds the IP address for the specified host and connects to it using a socket on port 21. After connecting it will log into the server, enter passive mode. The application will then fork into two processes which will give the retrieve command and open another socket to the server on the port specified in the answer to entering passive mode respectively. The application only exits once the download is completed.

# Part 2 - Network Configuration

## EXP1

### Network architecture, experiment objectives, main configuration commands

First of all, we need to restart the network settings on TUXs and restart the switch to the startup config.

To configure Tux3 and Tux4, we use:

``` bash
ifconfig eth0 up // Connect the eth0
ifconfig eth0 [ip-address] // ip-address: tux3 = 172.16.40.1/24 & tux4 = 172.16.40.254/24
ifconfig // To check, if everything is setup correctly
```

Check connectivity and capture using wireshark.

### What are ARP packets and what are they used for?

ARP (Address Resolution Protocol) packets allow for the translation of IP (Internet Protocol) addresses to MAC (Media Access Control) addresses. This is needed since to send a frame to another interface, an interface needs to know its MAC address but an IP address is convenient way to refer to an interface.

### What are the MAC and IP addresses of ARP packets and why?

Both MAC adresses and IP adresses uniquely define a device on the internet. The MAC address ensures the physical address of an interface, the IP address identifies the connection of the interface with the network.

### What packets does the ping command generate?

*ping* generates ICMP (Internet Control Message Protocol) packets.

### What are the MAC and IP Addresses of the *ping* packets?

#### Tux43

**MAC** - 00:21:5a:61:2f:13

**IP**  - 172.16.40.1

#### Tux44

**MAC** - 00:21:5a:c3:78:76

**IP**  - 172.16.40.254

### How to determine if a receiving Ethernet frame is ARP, IP, ICMP?

By checking the type value in the Ethernet II we can discover its type, 0x0806 for ARP and 0x0800 for IPv4. To discover if an incoming frame has an ICMP layer by checking the its IPv4 field (the value should equal 0x01).

### How to determine the length of a receiving frame?

For an ICMP packet we add the 14 bytes of the Ethernet II layer to the total length specified in the IPv4 layer. For ARP packets we add de Ethernet II layer length to the ARP layer length.

### What is the loopback interface and why is it important?

A loopback interface is a logical, virtual interface. It is used to identify the device, it is the preferred method for this since it is always up.

## EXP2


### Network architecture, experiment objectives, main configuration commands

To configure the Tux2, we use the same commands as in EXP1 for tuxes 3 and 4.

Check the cables on switch and respective ports.

Than create and configure vlan40 and vlan41, with the corresponding ports.

Check connectivity and capture packets with wireshark: tux3 and tux4 can not reach tux2

### How to configure vlan40?

After logging into the switch we must first create the VLAN. To do this we use the following commands:

```
configure terminal
vlan 40 // creates the VLAN with id 40
end
```

We must then add the correct interfaces to the  VLAN:
```
configure terminal
interface fastethernet 0/1 // the 1 indicates the number of the ethernet port being used on the switch, it should be a port that is connected to tux 43 or 44
switchport mode access
switchport access vlan 40 // add the the ethernet port
end

configure terminal
interface fastethernet 0/2
switchport mode access
switchport access vlan 40
end
```

After this we should have configured VLAN 40 correctly, to verify we can use:

```
show vlan id 40
```

### How many broadcast domains are there? How can you conclude it from the logs?

There are two broadcast domains, one for each VLAN (172.16.40.255 and 172.16.41.255). We can conclude this since a ping from tux43 can reach both itself and tux44 (both in VLAN 40) but cannot reach tux42, in  VLAN 41.

## EXP3

### What does NAT do?

NAT stands for Network Address Translation and it is a way to map multiple private addresses to a public one before transferring information.

### How to configure the DNS service at a host?

Alter the value of nameserver in /etc/resolv.conf

### What packets are exchanged by DNS and what informations is transported?

DNS exchanges either TCP or UDP packets and these transport information related to the IP address of a ceratin domain name.

### What ICMP packets are observed?

#### Source

**IP**  - 10.0.2.2
**MAC** - 52:54:00:12:35:02

#### Destination

**IP**  - 10.0.2.15
**MAC** - 08:00:27:bc:e2:1a

## EXP4

### Network architecture, experiment objectives, main configuration commands

Connect tux4 to vlan41: configure eth1 from tux4 and add another port to vlan41.

Configure tux4: enable IP forwarding and disable ICMP echo ignore broadcast.

Configure routes in tux2 and tux3 to reach vlan40 and vlan41, respectively.

Check connectivity and capture packets using wireshark: tux2 and tux3 can now reach each other.

Restart router and check ethernet cables connects.

Add other port to vlan41 to reach router.

Configure the fastethernet ports to reach vlan41(inside) and internet(outside).


### What information does an entry of the forwarding table contain?

An entry contains the destination IP address, the gateway IP address through which the data will be routed to the destination, the netmask, the route flags, a metric used to choose the fastest route, the number of references to the route, a count of route lookups and the interface to which packets will be sent.

### What routes are there in the tuxes?

Each tux has a route to VLAN 40 and VLAN 41. The routes from tux42 to VLAN 41, tux 43 to VLAN 40, and tux 44 to both VLANs are routed through 0.0.0.0 (meaning they are direct routes with no need for hops). In the route from tux 42 to VLAN 40 the specified gateway is the IP address for the interface in tux 44 in VLAN 41, in tux 43 the route to VLAN 41 is routed through tux 44.

### What ARP messages, and associated MAC addresses, are observed and why?

In the beginning all ARP tables are empty. After executing requests, the ARP table contains the required MAC addresses to reach the specified IPs in the request.

### What are the IP and MAC addresses associated to ICMP packets and why?

The ICMP packets being transmitted are related to ping requests and replies.

## Testing the download application

After finishing the 4th experiment, we had an established connection to the internet and were able to demonstrate it through the download application.

# Conclusion

The project allowed us to configure a network and gain a better understanding of the workings of a computer network and the internet. We were also able to study and create a download application that uses FTP.
