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

The download application parses the username, password, host and path from the specified URL (if the username and password aren't specified the application will attempt an anonymous login). The application finds the IP address for the specified host and connects to it using a socket on port 21. After connecting it will log into the server and enter passive mode. The application will then fork into two processes which will give the retrieve command and open another socket to the server on the port specified in the answer to entering passive mode respectively. The application only exits once the download is completed.

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

By checking the type value in the Ethernet II we can discover its type, 0x0806 for ARP and 0x0800 for IPv4. To discover if an incoming frame has an ICMP layer we check its IPv4 field (the value should equal 0x01).

### How to determine the length of a receiving frame?

For an ICMP packet we add the 14 bytes of the Ethernet II layer to the total length specified in the IPv4 layer. For ARP packets we add de Ethernet II layer length to the ARP layer length.

### What is the loopback interface and why is it important?

A loopback interface is a logical, virtual interface. It is used to identify the device, it is the preferred method for this since it is always up.

## EXP2


### Network architecture, experiment objectives, main configuration commands

To configure the Tux2, we use the same commands as in EXP1 for tuxes 3 and 4 (only changing the IP address).

Check the cables on switch and respective ports.

Then create and configure vlan40 and vlan41, with the corresponding ports.

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

Restart router and check ethernet cables connections.

Add another port to vlan41 to reach router.

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

# Annexes

## Code

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/wait.h>

struct User {
    char * name;
    char * password;
};

enum message_type {
    USER,
    PASS,
    PASV,
    RETR
};

char * read_response(int sockfd) {
    char * ans = malloc(2048);
    size_t n = 0;
    FILE * fp = fdopen(sockfd, "r");
    while (getline(&ans, &n, fp) != - 1)
    {
        printf("%s", ans);
        if(ans[3] == ' ') break;
    }

    return ans;
}

int send_message(int sockfd, enum message_type type, char * info) {
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));

    switch (type)
    {
    case USER:
        snprintf(buffer, sizeof(buffer), "user %s\r\n", info);
        break;
    case PASS:
        snprintf(buffer, sizeof(buffer), "pass %s\r\n", info);
        break;
    case PASV:
        snprintf(buffer, sizeof(buffer), "pasv\r\n");
        break;
    case RETR:
        snprintf(buffer, sizeof(buffer), "retr %s\r\n", info);
        break;
    default:
        break;
    }

    printf("%s\n", buffer);

    return send(sockfd, buffer, strlen(buffer), 0);
}

int check_response(char * response, enum message_type type) {
    switch (type)
    {
    case USER:
        return strcmp("331 Please specify the password.\r\n", response) == 0;
    case PASS:
        return strcmp("230 Login successful.\r\n", response) == 0;
    case PASV:
        return strstr(response, "227 Entering Passive Mode") != NULL;
    case RETR:
        return strstr(response, "150 Opening BINARY mode data connection for") != NULL;
    default:
        return 0;
    }
}

char * send_and_check_message(int sockfd, enum message_type type, char * info) {
    send_message(sockfd, type, info);
    char * ans = read_response(sockfd);
    if (check_response(ans, type)) {
        return ans;
    } else {
        free(ans);
        return NULL;
    }
}

void print_usage() {
    printf("ftp://[<user>:<password>@]<host>/<url-path>\n");
}

int main(int argc, char ** argv) {
    if (argc < 2)
        print_usage();

    char info[256], temp[256];

    strncpy(info, argv[1] + 6, strlen(argv[1]) - 5);

    char * at;

    struct User user = {"anonymous", "password"};
    char host[256] = {0};
    char path[256] = {0};

    int host_index = 0;
    int path_index = 0;
    int info_index = 0;

    if ((at = strstr(info, "@")) != NULL) {
        strcpy(temp, info);
        user.name = strtok(temp, ":");
        user.password = strtok(NULL, "@");
        strcpy(info, at+1);
    }

    printf("Username: %s, Password: %s\n", user.name, user.password);

    while(info[info_index] != '/') {
        host[host_index] = info[info_index];
        host_index++;
        info_index++;
    }

    info_index++;

    while(info[info_index] != '\0') {
        path[path_index] = info[info_index];
        path_index++;
        info_index++;
    }

    struct hostent *host_struct;

    if ((host_struct = gethostbyname(host)) == NULL) {
        herror("gethostbyname()");
        exit(-1);
    }

    int sockfd;
    struct sockaddr_in server_addr;
    char buf[256];
    size_t bytes;

    /*server address handling*/
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr *) host_struct->h_addr)));    /*32 bit Internet address network byte ordered*/
    server_addr.sin_port = htons(21);        /*server TCP port must be network byte ordered */

    /*open a TCP socket*/
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        exit(-1);
    }

    /*connect to the server*/
    if (connect(sockfd,
                (struct sockaddr *) &server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect()");
        exit(-1);
    }

    char * ans;
    int status;
    bool over = false;

    printf("Beginning conection\n");

    if ((ans = read_response(sockfd)) == NULL) exit(-1);

    free(ans);

    printf("Connection established. Logging in\n");

    if ((ans = send_and_check_message(sockfd, USER, user.name)) == NULL) exit(-1);

    free(ans);

    if ((ans = send_and_check_message(sockfd, PASS, user.password)) == NULL) exit(-1);

    free(ans);

    printf("Logged in. Entering passive mode\n");

    if ((ans = send_and_check_message(sockfd, PASV, NULL)) == NULL) exit(-1);

    int n0, n1;

    printf("Ans: %s\n", ans);

    sscanf(ans, "227 Entering Passive Mode (%*d,%*d,%*d,%*d,%d,%d)\r\n", &n0, &n1);

    free(ans);

    int port = n0 * 256 + n1;
    int id;

    printf("n0: %d, n1: %d, port: %d\n", n0, n1, port);

    switch ((id = fork()))
    {
    case 0:
        printf("Downloader proccess started\n");

        bzero((char *) &server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr *) host_struct->h_addr)));    /*32 bit Internet address network byte ordered*/
        server_addr.sin_port = htons(port);        /*server TCP port must be network byte ordered */

        /*open a TCP socket*/
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket()");
            exit(-1);
        }

        /*connect to the server*/
        if (connect(sockfd,
                    (struct sockaddr *) &server_addr,
                    sizeof(server_addr)) < 0) {
            perror("connect()");
            exit(-1);
        }

        printf("Downloader: Connection established\n");

        char filename[256];

        int info_index = 0, filename_index = 0;
        while(1){
            char c = info[info_index++];
            if(c == '\0') break;
            if(c == '/') {
                memset(filename, 0, sizeof(filename));
                filename_index = 0;
                continue;
            }
            filename[filename_index] = c;
            filename_index++;
        }

        printf("Downloader: Filename: %s\n", filename);

        char packet[256];
        int bytes;

        int file_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0777);

        while((bytes = recv(sockfd, packet, 256, 0)) > 0) {
            write(file_fd, packet, bytes);
        }

        printf("Downloader: File downloaded\n");

        close(file_fd);

        break;    
    default:
        printf("Parent: sending RETR message\n");
        send_message(sockfd, RETR, path);

        memset(ans, 0, 2048);

        printf("Parent: Waiting for downloader to terminate\n");

        waitpid(id, NULL, 0);

        sleep(1);

        recv(sockfd, ans, 2047, 0);

        printf("%s\n", ans);

        break;
    }

    return 0;
}
```

## Captures

### EXP 1

|No.|Time        |Source                  |Destination                   |Protocol|Length|Info                                                                                                                                                                                                                                                                                         |
|---|------------|------------------------|------------------------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:83          |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|2  |0.385897410 |Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. TC + Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                         |
|3  |1.294283288 |fe80::221:5aff:fec3:7876|ff02::fb                      |MDNS    |180   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|4  |2.390890029 |Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|5  |3.707632118 |fe80::221:5aff:fec3:7876|ff02::2                       |ICMPv6  |70    |Router Solicitation from 00:21:5a:c3:78:76                                                                                                                                                                                                                                                   |
|6  |4.135611390 |Cisco_7c:8f:83          |CDP/VTP/DTP/PAgP/UDLD         |DTP     |60    |Dynamic Trunk Protocol                                                                                                                                                                                                                                                                       |
|7  |4.135709518 |Cisco_7c:8f:83          |CDP/VTP/DTP/PAgP/UDLD         |DTP     |90    |Dynamic Trunk Protocol                                                                                                                                                                                                                                                                       |
|8  |4.399666640 |Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|9  |6.400555670 |Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|10 |8.133191432 |Cisco_7c:8f:83          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/3                                                                                                                                                                                                                                                 |
|11 |8.405484384 |Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|12 |9.999213602 |Cisco_7c:8f:83          |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|13 |10.410315807|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|14 |12.415295785|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|15 |12.754355835|fe80::221:5aff:fe61:2f13|ff02::fb                      |MDNS    |180   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|16 |13.107394911|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=1/256, ttl=64 (reply in 17)                                                                                                                                                                                                                              |
|17 |13.107548914|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=1/256, ttl=64 (request in 16)                                                                                                                                                                                                                            |
|18 |14.136252012|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=2/512, ttl=64 (reply in 19)                                                                                                                                                                                                                              |
|19 |14.136379684|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=2/512, ttl=64 (request in 18)                                                                                                                                                                                                                            |
|20 |14.424090625|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|21 |15.160257022|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=3/768, ttl=64 (reply in 22)                                                                                                                                                                                                                              |
|22 |15.160388535|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=3/768, ttl=64 (request in 21)                                                                                                                                                                                                                            |
|23 |16.184257562|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=4/1024, ttl=64 (reply in 24)                                                                                                                                                                                                                             |
|24 |16.184388237|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=4/1024, ttl=64 (request in 23)                                                                                                                                                                                                                           |
|25 |16.424995509|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|26 |17.208261664|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=5/1280, ttl=64 (reply in 27)                                                                                                                                                                                                                             |
|27 |17.208424257|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=5/1280, ttl=64 (request in 26)                                                                                                                                                                                                                           |
|28 |18.232246838|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=6/1536, ttl=64 (reply in 29)                                                                                                                                                                                                                             |
|29 |18.232374301|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=6/1536, ttl=64 (request in 28)                                                                                                                                                                                                                           |
|30 |18.299617514|HewlettP_c3:78:76       |HewlettP_61:2f:13             |ARP     |60    |Who has 172.16.40.1? Tell 172.16.40.254                                                                                                                                                                                                                                                      |
|31 |18.299625057|HewlettP_61:2f:13       |HewlettP_c3:78:76             |ARP     |42    |172.16.40.1 is at 00:21:5a:61:2f:13                                                                                                                                                                                                                                                          |
|32 |18.429853542|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|33 |19.256236273|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=7/1792, ttl=64 (reply in 34)                                                                                                                                                                                                                             |
|34 |19.256362548|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=7/1792, ttl=64 (request in 33)                                                                                                                                                                                                                           |
|35 |20.007025014|Cisco_7c:8f:83          |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|36 |20.280241003|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=8/2048, ttl=64 (reply in 37)                                                                                                                                                                                                                             |
|37 |20.280366161|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=8/2048, ttl=64 (request in 36)                                                                                                                                                                                                                           |
|38 |20.434746148|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|39 |21.304246223|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=9/2304, ttl=64 (reply in 40)                                                                                                                                                                                                                             |
|40 |21.304390098|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=9/2304, ttl=64 (request in 39)                                                                                                                                                                                                                           |
|41 |22.328267995|172.16.40.1             |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7339, seq=10/2560, ttl=64 (reply in 42)                                                                                                                                                                                                                            |
|42 |22.328430378|172.16.40.254           |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7339, seq=10/2560, ttl=64 (request in 41)                                                                                                                                                                                                                          |
|43 |22.439673185|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|44 |24.448629012|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|45 |26.396218234|HewlettP_61:2f:13       |HewlettP_c3:78:76             |ARP     |42    |Who has 172.16.40.254? Tell 172.16.40.1                                                                                                                                                                                                                                                      |
|46 |26.396332287|HewlettP_c3:78:76       |HewlettP_61:2f:13             |ARP     |60    |172.16.40.254 is at 00:21:5a:c3:78:76                                                                                                                                                                                                                                                        |
|47 |26.449442332|Cisco_7c:8f:83          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/1/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                              |
|48 |26.549917327|172.16.40.254           |224.0.0.251                   |MDNS    |160   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|49 |26.648223855|fe80::221:5aff:fe61:2f13|ff02::2                       |ICMPv6  |70    |Router Solicitation from 00:21:5a:61:2f:13                                                                                                                                                                                                                                                   |
### EXP 2

#### Question 4

|No.|Time        |Source           |Destination                   |Protocol|Length|Info                                                                                                                                                                                                                                                                                         |
|---|------------|-----------------|------------------------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|2  |2.004834916 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|3  |4.013713147 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|4  |6.014613002 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|5  |7.130235943 |Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|6  |8.019450293 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|7  |10.024386829|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|8  |11.280413035|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=1/256, ttl=64 (reply in 9)                                                                                                                                                                                                                               |
|9  |11.280576955|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=1/256, ttl=64 (request in 8)                                                                                                                                                                                                                             |
|10 |12.033377996|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|11 |12.287304283|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=2/512, ttl=64 (reply in 12)                                                                                                                                                                                                                              |
|12 |12.287436774|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=2/512, ttl=64 (request in 11)                                                                                                                                                                                                                            |
|13 |13.311315159|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=3/768, ttl=64 (reply in 14)                                                                                                                                                                                                                              |
|14 |13.311449676|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=3/768, ttl=64 (request in 13)                                                                                                                                                                                                                            |
|15 |14.034139144|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|16 |14.335306270|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=4/1024, ttl=64 (reply in 17)                                                                                                                                                                                                                             |
|17 |14.335465930|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=4/1024, ttl=64 (request in 16)                                                                                                                                                                                                                           |
|18 |15.359311839|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=5/1280, ttl=64 (reply in 19)                                                                                                                                                                                                                             |
|19 |15.359451384|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=5/1280, ttl=64 (request in 18)                                                                                                                                                                                                                           |
|20 |16.039079382|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|21 |16.383321458|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=6/1536, ttl=64 (reply in 22)                                                                                                                                                                                                                             |
|22 |16.383452762|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=6/1536, ttl=64 (request in 21)                                                                                                                                                                                                                           |
|23 |16.415275892|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |Who has 172.16.40.254? Tell 172.16.40.1                                                                                                                                                                                                                                                      |
|24 |16.415394135|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |172.16.40.254 is at 00:21:5a:c3:78:76                                                                                                                                                                                                                                                        |
|25 |16.514868428|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |Who has 172.16.40.1? Tell 172.16.40.254                                                                                                                                                                                                                                                      |
|26 |16.514884283|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |172.16.40.1 is at 00:21:5a:61:2f:13                                                                                                                                                                                                                                                          |
|27 |17.129482163|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|28 |17.407305445|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=7/1792, ttl=64 (reply in 29)                                                                                                                                                                                                                             |
|29 |17.407435632|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=7/1792, ttl=64 (request in 28)                                                                                                                                                                                                                           |
|30 |18.043973314|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|31 |18.431318697|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=8/2048, ttl=64 (reply in 32)                                                                                                                                                                                                                             |
|32 |18.431447626|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=8/2048, ttl=64 (request in 31)                                                                                                                                                                                                                           |
|33 |19.455318049|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=9/2304, ttl=64 (reply in 34)                                                                                                                                                                                                                             |
|34 |19.455481480|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=9/2304, ttl=64 (request in 33)                                                                                                                                                                                                                           |
|35 |20.048795728|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|36 |20.479305528|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x7471, seq=10/2560, ttl=64 (reply in 37)                                                                                                                                                                                                                            |
|37 |20.479439905|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7471, seq=10/2560, ttl=64 (request in 36)                                                                                                                                                                                                                          |
|38 |21.491238070|172.16.40.254    |224.0.0.251                   |MDNS    |160   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|39 |22.057787593|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|40 |24.058560405|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|41 |26.063520548|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|42 |27.137206201|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|43 |28.068343031|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|44 |30.073251840|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|45 |32.082171977|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
|46 |34.083122887|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003                                                                                                                                                                                                                             |
#### Question 7

##### Tux 2

|No.|Time        |Source        |Destination                   |Protocol|Length|Info                                                                                                                                                                                                                                                                                         |
|---|------------|--------------|------------------------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|2  |0.125746925 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|3  |2.134568189 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|4  |4.135414460 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|5  |6.140283253 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|6  |8.145177538 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|7  |10.007638993|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|8  |10.150081532|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|9  |12.159069787|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|10 |14.160166998|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|11 |16.164716406|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|12 |18.169687517|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|13 |20.007020833|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|14 |20.174506723|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|15 |22.183402578|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|16 |23.043606090|172.16.41.1   |224.0.0.251                   |MDNS    |160   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|17 |24.184312405|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|18 |26.189164855|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|19 |28.194047686|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|20 |30.014585235|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|21 |30.198926676|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|22 |32.207871071|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|23 |34.208783552|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|24 |36.213633558|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|25 |38.218476509|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|26 |40.022236380|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|27 |40.223359061|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|28 |42.232348085|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|29 |44.233184438|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|30 |46.238019638|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|31 |48.242956736|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|32 |48.922812345|Cisco_7c:8f:82|CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/2                                                                                                                                                                                                                                                 |
|33 |50.034005311|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|34 |50.247890691|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|35 |52.256731511|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|36 |54.257576176|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|37 |56.262469553|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|38 |58.267368588|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|39 |60.029214818|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|40 |60.272268390|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|41 |62.281142804|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|42 |64.282011215|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|43 |66.286971710|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|44 |68.291782185|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|45 |70.040889044|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|46 |70.296676331|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|47 |72.305808110|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|48 |74.306489276|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|49 |76.311333345|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|50 |78.316220996|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
|51 |80.044497134|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|52 |80.321106621|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002                                                                                                                                                                                                                             |
##### Tux 3

|No.|Time        |Source           |Destination                   |Protocol|Length|Info                                                                    |
|---|------------|-----------------|------------------------------|--------|------|------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|2  |0.973316331 |Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|3  |2.004914746 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|4  |4.009774944 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|5  |6.018725253 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|6  |8.019541088 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|7  |10.024416023|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|8  |10.980714624|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|9  |12.029310235|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|10 |14.034311445|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|11 |16.043080792|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|12 |18.044009422|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|13 |18.866400730|Cisco_7c:8f:83   |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/3                            |
|14 |20.048872624|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|15 |20.992636960|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|16 |22.053743788|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|17 |24.058647638|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|18 |26.067545216|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|19 |28.068537263|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|20 |30.073335581|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|21 |30.995994940|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|22 |32.078181881|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|23 |34.083085940|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|24 |36.092009150|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|25 |38.092841887|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|26 |40.098010649|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|27 |40.999529972|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|28 |42.102704693|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|29 |44.107531297|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|30 |46.116492990|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|31 |48.117300584|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|32 |50.122165881|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|33 |51.002927833|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|34 |52.127120576|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|35 |54.131987968|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|36 |56.140848879|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|37 |58.141719121|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|38 |60.146618640|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|39 |61.010615554|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|40 |62.151501328|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|41 |64.156464195|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|42 |66.165337747|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|43 |68.166441821|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|44 |70.171047794|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|45 |71.018264721|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|46 |72.175933275|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|47 |74.180814985|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|48 |75.097802164|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=1/256, ttl=64 (no response found!)  |
|49 |75.097974884|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=1/256, ttl=64                       |
|50 |76.101696404|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=2/512, ttl=64 (no response found!)  |
|51 |76.101863467|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=2/512, ttl=64                       |
|52 |76.190241200|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|53 |77.125692265|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=3/768, ttl=64 (no response found!)  |
|54 |77.125859886|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=3/768, ttl=64                       |
|55 |78.149690779|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=4/1024, ttl=64 (no response found!) |
|56 |78.149860077|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=4/1024, ttl=64                      |
|57 |78.194519262|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|58 |78.874836534|Cisco_7c:8f:83   |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/3                            |
|59 |79.173691878|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=5/1280, ttl=64 (no response found!) |
|60 |79.173855728|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=5/1280, ttl=64                      |
|61 |80.105313134|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |Who has 172.16.40.1? Tell 172.16.40.254                                 |
|62 |80.105332201|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |172.16.40.1 is at 00:21:5a:61:2f:13                                     |
|63 |80.195544973|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|64 |80.197679287|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=6/1536, ttl=64 (no response found!) |
|65 |80.197819321|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=6/1536, ttl=64                      |
|66 |81.017669622|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                                   |
|67 |81.221691421|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=7/1792, ttl=64 (no response found!) |
|68 |81.221843887|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=7/1792, ttl=64                      |
|69 |82.200373254|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|70 |82.245693776|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=8/2048, ttl=64 (no response found!) |
|71 |82.245844776|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=8/2048, ttl=64                      |
|72 |83.269692989|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=9/2304, ttl=64 (no response found!) |
|73 |83.269862637|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=9/2304, ttl=64                      |
|74 |84.205279199|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|75 |84.293685847|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=10/2560, ttl=64 (no response found!)|
|76 |84.293839220|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=10/2560, ttl=64                     |
|77 |86.214154288|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |
|78 |88.215081940|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003        |

##### Tux 4

|No.|Time        |Source           |Destination                   |Protocol|Length|Info                                                                    |
|---|------------|-----------------|------------------------------|--------|------|------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|2  |1.999464108 |Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|3  |4.005334126 |Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|4  |4.885067565 |Cisco_7c:8f:84   |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                   |
|5  |6.011115306 |Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|6  |8.014847693 |Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|7  |10.024438154|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|8  |12.024029862|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|9  |14.029833671|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|10 |14.892744098|Cisco_7c:8f:84   |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                   |
|11 |16.033771879|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|12 |18.039572266|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|13 |20.049294447|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|14 |22.048832448|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|15 |24.054607691|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|16 |24.900391647|Cisco_7c:8f:84   |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                   |
|17 |26.058382052|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|18 |28.064264921|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|19 |28.979876927|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=1/256, ttl=64 (no response found!)  |
|20 |28.979913873|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=1/256, ttl=64                       |
|21 |29.983770228|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=2/512, ttl=64 (no response found!)  |
|22 |29.983803193|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=2/512, ttl=64                       |
|23 |30.074071750|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|24 |31.007765935|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=3/768, ttl=64 (no response found!)  |
|25 |31.007797573|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=3/768, ttl=64                       |
|26 |32.031763319|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=4/1024, ttl=64 (no response found!) |
|27 |32.031798519|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=4/1024, ttl=64                      |
|28 |32.077811959|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|29 |32.685319293|Cisco_7c:8f:84   |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/4                            |
|30 |33.055761191|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=5/1280, ttl=64 (no response found!) |
|31 |33.055794436|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=5/1280, ttl=64                      |
|32 |33.987247694|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |42    |Who has 172.16.40.1? Tell 172.16.40.254                                 |
|33 |33.987387307|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |60    |172.16.40.1 is at 00:21:5a:61:2f:13                                     |
|34 |34.077689668|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|35 |34.079738880|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=6/1536, ttl=64 (no response found!) |
|36 |34.079760461|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=6/1536, ttl=64                      |
|37 |34.899793460|Cisco_7c:8f:84   |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                   |
|38 |35.103754841|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=7/1792, ttl=64 (no response found!) |
|39 |35.103783267|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=7/1792, ttl=64                      |
|40 |36.083580987|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|41 |36.127756206|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=8/2048, ttl=64 (no response found!) |
|42 |36.127783235|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=8/2048, ttl=64                      |
|43 |37.151764974|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=9/2304, ttl=64 (no response found!) |
|44 |37.151799406|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=9/2304, ttl=64                      |
|45 |38.087427285|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|46 |38.175747132|172.16.40.1      |172.16.40.255                 |ICMP    |98    |Echo (ping) request  id=0x7507, seq=10/2560, ttl=64 (no response found!)|
|47 |38.175776186|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7507, seq=10/2560, ttl=64                     |
|48 |40.097311778|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|49 |42.098940267|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|50 |44.102497352|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|51 |44.907349447|Cisco_7c:8f:84   |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                   |
|52 |46.108372119|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|53 |48.112032918|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|54 |50.121701951|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |
|55 |52.123360262|Cisco_7c:8f:84   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004        |

#### Question 10

##### Tux 2

|No.|Time        |Source        |Destination                   |Protocol|Length|Info                                                                    |
|---|------------|--------------|------------------------------|--------|------|------------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|2  |1.539271868 |Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                   |
|3  |2.004777091 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|4  |4.013789442 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|5  |6.014581306 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|6  |8.019708793 |Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|7  |10.024327134|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|8  |11.542856211|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                   |
|9  |12.029263254|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|10 |14.038158062|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|11 |16.038988898|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|12 |18.043881577|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|13 |20.048788433|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|14 |21.546222649|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                   |
|15 |22.053647379|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|16 |24.062604136|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|17 |26.063429105|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|18 |28.070388255|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|19 |30.073194488|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|20 |30.572663222|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=1/256, ttl=64 (no response found!)  |
|21 |31.549786110|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                   |
|22 |31.577836907|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=2/512, ttl=64 (no response found!)  |
|23 |32.078076412|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|24 |32.601841961|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=3/768, ttl=64 (no response found!)  |
|25 |33.625838074|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=4/1024, ttl=64 (no response found!) |
|26 |34.087045181|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|27 |34.649837331|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=5/1280, ttl=64 (no response found!) |
|28 |35.673839940|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=6/1536, ttl=64 (no response found!) |
|29 |36.087868684|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|30 |36.697843945|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=7/1792, ttl=64 (no response found!) |
|31 |37.721841875|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=8/2048, ttl=64 (no response found!) |
|32 |38.092801591|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|33 |38.745836731|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=9/2304, ttl=64 (no response found!) |
|34 |39.769840318|172.16.41.1   |172.16.41.255                 |ICMP    |98    |Echo (ping) request  id=0x7225, seq=10/2560, ttl=64 (no response found!)|
|35 |40.097635883|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |
|36 |41.557503046|Cisco_7c:8f:82|Cisco_7c:8f:82                |LOOP    |60    |Reply                                                                   |
|37 |42.102529959|Cisco_7c:8f:82|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8002        |

##### Tux 3

|No.|Time        |Source        |Destination                   |Protocol|Length|Info                                                            |
|---|------------|--------------|------------------------------|--------|------|----------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|2  |2.009032932 |Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|3  |4.009791007 |Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|4  |4.404463835 |Cisco_7c:8f:83|CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/3                    |
|5  |6.016753532 |Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|6  |6.610197407 |Cisco_7c:8f:83|Cisco_7c:8f:83                |LOOP    |60    |Reply                                                           |
|7  |8.019549608 |Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|8  |10.024464074|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|9  |12.033326172|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|10 |14.034263393|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|11 |16.039105572|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|12 |16.617884219|Cisco_7c:8f:83|Cisco_7c:8f:83                |LOOP    |60    |Reply                                                           |
|13 |18.043992800|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|14 |20.048877652|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|15 |22.057817276|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|16 |24.058677251|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|17 |26.063532001|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|18 |26.617305045|Cisco_7c:8f:83|Cisco_7c:8f:83                |LOOP    |60    |Reply                                                           |
|19 |28.068473357|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|20 |30.073333835|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|21 |32.082283026|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|22 |34.083079864|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|23 |36.088039867|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|24 |36.624834782|Cisco_7c:8f:83|Cisco_7c:8f:83                |LOOP    |60    |Reply                                                           |
|25 |38.092876109|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|26 |40.097748251|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|
|27 |42.106668667|Cisco_7c:8f:83|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003|

##### Tux 4

|No.|Time        |Source        |Destination                   |Protocol|Length|Info                                                            |
|---|------------|--------------|------------------------------|--------|------|----------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|2  |2.005630323 |Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|3  |4.013256359 |Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|4  |6.014682378 |Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|5  |8.020255990 |Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|6  |8.597302621 |Cisco_7c:8f:84|Cisco_7c:8f:84                |LOOP    |60    |Reply                                                           |
|7  |10.023858192|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|8  |12.029486629|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|9  |14.038961014|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|10 |16.038561942|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|11 |18.044185350|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|12 |18.596721125|Cisco_7c:8f:84|Cisco_7c:8f:84                |LOOP    |60    |Reply                                                           |
|13 |20.048057419|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|14 |22.053874497|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|15 |24.061771797|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|16 |26.063388273|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|17 |28.069226513|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|18 |28.604251481|Cisco_7c:8f:84|Cisco_7c:8f:84                |LOOP    |60    |Reply                                                           |
|19 |30.072976221|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|20 |32.078772626|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|21 |34.086392796|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|22 |36.088044961|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|23 |38.093618363|Cisco_7c:8f:84|Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004|
|24 |38.616077074|Cisco_7c:8f:84|Cisco_7c:8f:84                |LOOP    |60    |Reply                                                           |

### EXP 3

#### DNS

##### Question 2

|No.|Time        |Source                   |Destination    |Protocol|Length|Info                                                                                                                                        |
|---|------------|-------------------------|---------------|--------|------|--------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000 |10.0.2.15                |193.136.28.10  |DNS     |100   |Standard query 0xeded A connectivity-check.ubuntu.com OPT                                                                                   |
|2  |0.015703237 |193.136.28.10            |10.0.2.15      |DNS     |132   |Standard query response 0xeded A connectivity-check.ubuntu.com A 35.232.111.17 A 35.224.170.84 OPT                                          |
|3  |0.017566298 |10.0.2.15                |35.224.170.84  |TCP     |74    |57162  >  80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4066455018 TSecr=0 WS=128                                               |
|4  |1.031748699 |10.0.2.15                |35.224.170.84  |TCP     |74    |[TCP Retransmission] [TCP Port numbers reused] 57162  >  80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4066456032 TSecr=0 WS=128|
|5  |3.047504183 |10.0.2.15                |35.224.170.84  |TCP     |74    |[TCP Retransmission] [TCP Port numbers reused] 57162  >  80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=4066458048 TSecr=0 WS=128|
|6  |3.167161897 |35.224.170.84            |10.0.2.15      |TCP     |60    |80  >  57162 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460                                                                                |
|7  |3.167206927 |10.0.2.15                |35.224.170.84  |TCP     |54    |57162  >  80 [ACK] Seq=1 Ack=1 Win=64240 Len=0                                                                                              |
|8  |3.167321680 |10.0.2.15                |35.224.170.84  |HTTP    |141   |GET / HTTP/1.1                                                                                                                              |
|9  |3.167550439 |35.224.170.84            |10.0.2.15      |TCP     |60    |80  >  57162 [ACK] Seq=1 Ack=88 Win=65535 Len=0                                                                                             |
|10 |3.334118925 |35.224.170.84            |10.0.2.15      |HTTP    |202   |HTTP/1.1 204 No Content                                                                                                                     |
|11 |3.334136603 |10.0.2.15                |35.224.170.84  |TCP     |54    |57162  >  80 [ACK] Seq=88 Ack=149 Win=64092 Len=0                                                                                           |
|12 |3.334119186 |35.224.170.84            |10.0.2.15      |TCP     |60    |80  >  57162 [FIN, ACK] Seq=149 Ack=88 Win=65535 Len=0                                                                                      |
|13 |3.334323861 |10.0.2.15                |35.224.170.84  |TCP     |54    |57162  >  80 [FIN, ACK] Seq=88 Ack=150 Win=64091 Len=0                                                                                      |
|14 |3.334625070 |35.224.170.84            |10.0.2.15      |TCP     |60    |80  >  57162 [ACK] Seq=150 Ack=89 Win=65535 Len=0                                                                                           |
|15 |12.982419748|fe80::cb41:929d:3005:c87f|ff02::fb       |MDNS    |102   |Standard query 0x0000 PTR _pgpkey-hkp._tcp.local, "QM" question                                                                             |
|16 |12.982492668|10.0.2.15                |224.0.0.251    |MDNS    |82    |Standard query 0x0000 PTR _pgpkey-hkp._tcp.local, "QM" question                                                                             |
|17 |17.685343270|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=1/256, ttl=64 (reply in 18)                                                                             |
|18 |17.715641400|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=1/256, ttl=113 (request in 17)                                                                          |
|19 |18.686381579|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=2/512, ttl=64 (reply in 20)                                                                             |
|20 |18.716291735|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=2/512, ttl=113 (request in 19)                                                                          |
|21 |19.733801456|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=3/768, ttl=64 (reply in 22)                                                                             |
|22 |19.762257556|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=3/768, ttl=113 (request in 21)                                                                          |
|23 |20.736054010|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=4/1024, ttl=64 (reply in 24)                                                                            |
|24 |20.764503196|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=4/1024, ttl=113 (request in 23)                                                                         |
|25 |21.743205838|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=5/1280, ttl=64 (reply in 26)                                                                            |
|26 |21.771650786|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=5/1280, ttl=113 (request in 25)                                                                         |
|27 |22.798375512|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=6/1536, ttl=64 (reply in 28)                                                                            |
|28 |22.827100689|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=6/1536, ttl=113 (request in 27)                                                                         |
|29 |23.813452081|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=7/1792, ttl=64 (reply in 30)                                                                            |
|30 |23.841985089|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=7/1792, ttl=113 (request in 29)                                                                         |
|31 |24.834546917|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=8/2048, ttl=64 (reply in 32)                                                                            |
|32 |24.863457151|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=8/2048, ttl=113 (request in 31)                                                                         |
|33 |25.836051815|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=9/2304, ttl=64 (reply in 34)                                                                            |
|34 |25.865374570|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=9/2304, ttl=113 (request in 33)                                                                         |
|35 |26.838232169|10.0.2.15                |142.250.200.142|ICMP    |98    |Echo (ping) request  id=0x0001, seq=10/2560, ttl=64 (reply in 36)                                                                           |
|36 |26.869018105|142.250.200.142          |10.0.2.15      |ICMP    |98    |Echo (ping) reply    id=0x0001, seq=10/2560, ttl=113 (request in 35)                                                                        |

##### Question 3

|No.|Time        |Source                   |Destination      |Protocol|Length|Info                                                                                                                                                                                                                                                                                         |
|---|------------|-------------------------|-----------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000 |PcsCompu_bc:e2:1a        |RealtekU_12:35:02|ARP     |42    |Who has 10.0.2.2? Tell 10.0.2.15                                                                                                                                                                                                                                                             |
|2  |0.000192690 |RealtekU_12:35:02        |PcsCompu_bc:e2:1a|ARP     |60    |10.0.2.2 is at 52:54:00:12:35:02                                                                                                                                                                                                                                                             |
|3  |11.680437501|10.0.2.15                |193.136.28.10    |DNS     |86    |Standard query 0x1162 A enisa.europa.eu OPT                                                                                                                                                                                                                                                  |
|4  |11.680513032|10.0.2.15                |193.136.28.10    |DNS     |86    |Standard query 0xa48f AAAA enisa.europa.eu OPT                                                                                                                                                                                                                                               |
|5  |12.627497795|fe80::cb41:929d:3005:c87f|ff02::fb         |MDNS    |180   |Standard query 0x0000 PTR _ftp._tcp.local, "QM" question PTR _nfs._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question|
|6  |12.627606901|10.0.2.15                |224.0.0.251      |MDNS    |160   |Standard query 0x0000 PTR _ftp._tcp.local, "QM" question PTR _nfs._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question|
|7  |12.630020967|193.136.28.10            |10.0.2.15        |DNS     |114   |Standard query response 0xa48f AAAA enisa.europa.eu AAAA 2001:4d80:600::2 OPT                                                                                                                                                                                                                |
|8  |12.630021338|193.136.28.10            |10.0.2.15        |DNS     |102   |Standard query response 0x1162 A enisa.europa.eu A 212.146.105.104 OPT                                                                                                                                                                                                                       |
|9  |12.631352154|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=1/256, ttl=64 (reply in 10)                                                                                                                                                                                                                              |
|10 |12.719278780|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=1/256, ttl=43 (request in 9)                                                                                                                                                                                                                             |
|11 |12.719691934|10.0.2.15                |193.136.28.10    |DNS     |99    |Standard query 0x2f03 PTR 104.105.146.212.in-addr.arpa OPT                                                                                                                                                                                                                                   |
|12 |12.819852243|193.136.28.10            |10.0.2.15        |DNS     |128   |Standard query response 0x2f03 PTR 104.105.146.212.in-addr.arpa PTR enisa.europa.eu OPT                                                                                                                                                                                                      |
|13 |13.632813443|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=2/512, ttl=64 (reply in 14)                                                                                                                                                                                                                              |
|14 |13.718899484|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=2/512, ttl=43 (request in 13)                                                                                                                                                                                                                            |
|15 |14.633155912|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=3/768, ttl=64 (reply in 16)                                                                                                                                                                                                                              |
|16 |14.719421667|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=3/768, ttl=43 (request in 15)                                                                                                                                                                                                                            |
|17 |15.638712437|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=4/1024, ttl=64 (reply in 18)                                                                                                                                                                                                                             |
|18 |15.726652684|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=4/1024, ttl=43 (request in 17)                                                                                                                                                                                                                           |
|19 |16.641652587|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=5/1280, ttl=64 (reply in 20)                                                                                                                                                                                                                             |
|20 |16.727376109|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=5/1280, ttl=43 (request in 19)                                                                                                                                                                                                                           |
|21 |17.643137974|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=6/1536, ttl=64 (reply in 22)                                                                                                                                                                                                                             |
|22 |17.739139977|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=6/1536, ttl=43 (request in 21)                                                                                                                                                                                                                           |
|23 |18.644686230|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=7/1792, ttl=64 (reply in 24)                                                                                                                                                                                                                             |
|24 |18.735027583|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=7/1792, ttl=43 (request in 23)                                                                                                                                                                                                                           |
|25 |19.647407067|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=8/2048, ttl=64 (reply in 26)                                                                                                                                                                                                                             |
|26 |19.733067976|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=8/2048, ttl=43 (request in 25)                                                                                                                                                                                                                           |
|27 |20.650695462|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=9/2304, ttl=64 (reply in 28)                                                                                                                                                                                                                             |
|28 |20.736468797|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=9/2304, ttl=43 (request in 27)                                                                                                                                                                                                                           |
|29 |21.062889079|fe80::cb41:929d:3005:c87f|ff02::fb         |MDNS    |101   |Standard query 0x0000 PTR _nmea-0183._tcp.local, "QM" question                                                                                                                                                                                                                               |
|30 |21.062974966|10.0.2.15                |224.0.0.251      |MDNS    |81    |Standard query 0x0000 PTR _nmea-0183._tcp.local, "QM" question                                                                                                                                                                                                                               |
|31 |21.654173814|10.0.2.15                |212.146.105.104  |ICMP    |98    |Echo (ping) request  id=0x0002, seq=10/2560, ttl=64 (reply in 32)                                                                                                                                                                                                                            |
|32 |21.741947982|212.146.105.104          |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0002, seq=10/2560, ttl=43 (request in 31)                                                                                                                                                                                                                          |
|33 |25.881154132|10.0.2.15                |91.189.89.199    |NTP     |90    |NTP Version 4, client                                                                                                                                                                                                                                                                        |
|34 |25.997035111|91.189.89.199            |10.0.2.15        |NTP     |90    |NTP Version 4, server                                                                                                                                                                                                                                                                        |
##### Question 4

|No.|Time       |Source           |Destination      |Protocol|Length|Info                                                                                                                                   |
|---|-----------|-----------------|-----------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000|10.0.2.15        |9.9.9.9          |DNS     |84    |Standard query 0xeefa A parlamento.pt OPT                                                                                              |
|2  |0.000076636|10.0.2.15        |9.9.9.9          |DNS     |84    |Standard query 0x8501 AAAA parlamento.pt OPT                                                                                           |
|3  |0.024119506|9.9.9.9          |10.0.2.15        |DNS     |100   |Standard query response 0xeefa A parlamento.pt A 88.157.195.115 OPT                                                                    |
|4  |0.063752900|9.9.9.9          |10.0.2.15        |DNS     |134   |Standard query response 0x8501 AAAA parlamento.pt SOA ns2.parlamento.pt OPT                                                            |
|5  |0.064190903|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=1/256, ttl=64 (reply in 6)                                                                         |
|6  |0.087138320|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=1/256, ttl=115 (request in 5)                                                                      |
|7  |0.087393835|10.0.2.15        |9.9.9.9          |DNS     |98    |Standard query 0x5b9f PTR 115.195.157.88.in-addr.arpa OPT                                                                              |
|8  |0.149491442|9.9.9.9          |10.0.2.15        |DNS     |168   |Standard query response 0x5b9f PTR 115.195.157.88.in-addr.arpa PTR biblioteca.parlamento.pt PTR parlamento.pt PTR www.parlamento.pt OPT|
|9  |1.076495622|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=2/512, ttl=64 (reply in 10)                                                                        |
|10 |1.098289961|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=2/512, ttl=115 (request in 9)                                                                      |
|11 |2.077108852|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=3/768, ttl=64 (reply in 12)                                                                        |
|12 |2.218477334|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=3/768, ttl=115 (request in 11)                                                                     |
|13 |3.078459473|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=4/1024, ttl=64 (reply in 14)                                                                       |
|14 |3.101753775|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=4/1024, ttl=115 (request in 13)                                                                    |
|15 |4.079243489|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=5/1280, ttl=64 (reply in 16)                                                                       |
|16 |4.101260151|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=5/1280, ttl=115 (request in 15)                                                                    |
|17 |5.079415242|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=6/1536, ttl=64 (reply in 18)                                                                       |
|18 |5.103882506|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=6/1536, ttl=115 (request in 17)                                                                    |
|19 |5.119418900|PcsCompu_bc:e2:1a|RealtekU_12:35:02|ARP     |42    |Who has 10.0.2.2? Tell 10.0.2.15                                                                                                       |
|20 |5.119611660|RealtekU_12:35:02|PcsCompu_bc:e2:1a|ARP     |60    |10.0.2.2 is at 52:54:00:12:35:02                                                                                                       |
|21 |6.083735420|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=7/1792, ttl=64 (reply in 22)                                                                       |
|22 |6.105878710|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=7/1792, ttl=115 (request in 21)                                                                    |
|23 |7.085098347|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=8/2048, ttl=64 (reply in 24)                                                                       |
|24 |7.109948538|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=8/2048, ttl=115 (request in 23)                                                                    |
|25 |8.088229861|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=9/2304, ttl=64 (reply in 26)                                                                       |
|26 |8.109301128|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=9/2304, ttl=115 (request in 25)                                                                    |
|27 |9.090553104|10.0.2.15        |88.157.195.115   |ICMP    |98    |Echo (ping) request  id=0x0006, seq=10/2560, ttl=64 (reply in 28)                                                                      |
|28 |9.112758399|88.157.195.115   |10.0.2.15        |ICMP    |98    |Echo (ping) reply    id=0x0006, seq=10/2560, ttl=115 (request in 27)                                                                   |

#### Linux

##### Question 5

|No.|Time        |Source           |Destination      |Protocol|Length|Info                                                    |
|---|------------|-----------------|-----------------|--------|------|--------------------------------------------------------|
|1  |0.000000000 |10.0.2.15        |104.17.113.188   |UDP     |74    |37050  >  33434 Len=32                                  |
|2  |0.000064352 |10.0.2.15        |104.17.113.188   |UDP     |74    |51292  >  33435 Len=32                                  |
|3  |0.000093834 |10.0.2.15        |104.17.113.188   |UDP     |74    |33070  >  33436 Len=32                                  |
|4  |0.000123020 |10.0.2.15        |104.17.113.188   |UDP     |74    |49779  >  33437 Len=32                                  |
|5  |0.000154089 |10.0.2.15        |104.17.113.188   |UDP     |74    |53762  >  33438 Len=32                                  |
|6  |0.000184482 |10.0.2.15        |104.17.113.188   |UDP     |74    |46148  >  33439 Len=32                                  |
|7  |0.000218504 |10.0.2.15        |104.17.113.188   |UDP     |74    |59525  >  33440 Len=32                                  |
|8  |0.000252127 |10.0.2.15        |104.17.113.188   |UDP     |74    |52024  >  33441 Len=32                                  |
|9  |0.000290299 |10.0.2.15        |104.17.113.188   |UDP     |74    |44684  >  33442 Len=32                                  |
|10 |0.000354288 |10.0.2.15        |104.17.113.188   |UDP     |74    |51239  >  33443 Len=32                                  |
|11 |0.000385774 |10.0.2.2         |10.0.2.15        |ICMP    |70    |Time-to-live exceeded (Time to live exceeded in transit)|
|12 |0.000396744 |10.0.2.15        |104.17.113.188   |UDP     |74    |50600  >  33444 Len=32                                  |
|13 |0.000386026 |10.0.2.2         |10.0.2.15        |ICMP    |70    |Time-to-live exceeded (Time to live exceeded in transit)|
|14 |0.000386099 |10.0.2.2         |10.0.2.15        |ICMP    |70    |Time-to-live exceeded (Time to live exceeded in transit)|
|15 |0.000427566 |10.0.2.15        |104.17.113.188   |UDP     |74    |57740  >  33445 Len=32                                  |
|16 |0.000462035 |10.0.2.15        |104.17.113.188   |UDP     |74    |33814  >  33446 Len=32                                  |
|17 |0.000494118 |10.0.2.15        |104.17.113.188   |UDP     |74    |50838  >  33447 Len=32                                  |
|18 |0.000529294 |10.0.2.15        |104.17.113.188   |UDP     |74    |58616  >  33448 Len=32                                  |
|19 |0.000559324 |10.0.2.15        |104.17.113.188   |UDP     |74    |33328  >  33449 Len=32                                  |
|20 |0.000707492 |10.0.2.15        |104.17.113.188   |UDP     |74    |40420  >  33450 Len=32                                  |
|21 |0.000765823 |10.0.2.15        |104.17.113.188   |UDP     |74    |37251  >  33451 Len=32                                  |
|22 |0.000809737 |10.0.2.15        |104.17.113.188   |UDP     |74    |32915  >  33452 Len=32                                  |
|23 |5.016815232 |10.0.2.15        |104.17.113.188   |UDP     |74    |36373  >  33453 Len=32                                  |
|24 |5.016880349 |10.0.2.15        |104.17.113.188   |UDP     |74    |58281  >  33454 Len=32                                  |
|25 |5.016913483 |10.0.2.15        |104.17.113.188   |UDP     |74    |42681  >  33455 Len=32                                  |
|26 |5.016945079 |10.0.2.15        |104.17.113.188   |UDP     |74    |42657  >  33456 Len=32                                  |
|27 |5.016974729 |10.0.2.15        |104.17.113.188   |UDP     |74    |44173  >  33457 Len=32                                  |
|28 |5.017007061 |10.0.2.15        |104.17.113.188   |UDP     |74    |52025  >  33458 Len=32                                  |
|29 |5.017039515 |10.0.2.15        |104.17.113.188   |UDP     |74    |46690  >  33459 Len=32                                  |
|30 |5.017071322 |10.0.2.15        |104.17.113.188   |UDP     |74    |38542  >  33460 Len=32                                  |
|31 |5.017103202 |10.0.2.15        |104.17.113.188   |UDP     |74    |55158  >  33461 Len=32                                  |
|32 |5.017172830 |10.0.2.15        |104.17.113.188   |UDP     |74    |55229  >  33462 Len=32                                  |
|33 |5.017220268 |10.0.2.15        |104.17.113.188   |UDP     |74    |39875  >  33463 Len=32                                  |
|34 |5.017263496 |10.0.2.15        |104.17.113.188   |UDP     |74    |34598  >  33464 Len=32                                  |
|35 |5.017311138 |10.0.2.15        |104.17.113.188   |UDP     |74    |46940  >  33465 Len=32                                  |
|36 |5.017400247 |10.0.2.15        |104.17.113.188   |UDP     |74    |51802  >  33466 Len=32                                  |
|37 |5.017471073 |10.0.2.15        |104.17.113.188   |UDP     |74    |48714  >  33467 Len=32                                  |
|38 |5.017513585 |10.0.2.15        |104.17.113.188   |UDP     |74    |33989  >  33468 Len=32                                  |
|39 |5.066377838 |PcsCompu_bc:e2:1a|RealtekU_12:35:02|ARP     |42    |Who has 10.0.2.2? Tell 10.0.2.15                        |
|40 |5.066618082 |RealtekU_12:35:02|PcsCompu_bc:e2:1a|ARP     |60    |10.0.2.2 is at 52:54:00:12:35:02                        |
|41 |10.029808093|10.0.2.15        |104.17.113.188   |UDP     |74    |55661  >  33469 Len=32                                  |
|42 |10.029865806|10.0.2.15        |104.17.113.188   |UDP     |74    |51067  >  33470 Len=32                                  |
|43 |10.029895671|10.0.2.15        |104.17.113.188   |UDP     |74    |53611  >  33471 Len=32                                  |
|44 |10.029929656|10.0.2.15        |104.17.113.188   |UDP     |74    |48220  >  33472 Len=32                                  |
|45 |10.029959378|10.0.2.15        |104.17.113.188   |UDP     |74    |36368  >  33473 Len=32                                  |
|46 |10.030012901|10.0.2.15        |104.17.113.188   |UDP     |74    |43672  >  33474 Len=32                                  |
|47 |10.030067868|10.0.2.15        |104.17.113.188   |UDP     |74    |46524  >  33475 Len=32                                  |
|48 |10.030100744|10.0.2.15        |104.17.113.188   |UDP     |74    |60649  >  33476 Len=32                                  |
|49 |10.030136216|10.0.2.15        |104.17.113.188   |UDP     |74    |59496  >  33477 Len=32                                  |
|50 |10.030172251|10.0.2.15        |104.17.113.188   |UDP     |74    |49156  >  33478 Len=32                                  |
|51 |10.030214996|10.0.2.15        |104.17.113.188   |UDP     |74    |43501  >  33479 Len=32                                  |
|52 |10.030252199|10.0.2.15        |104.17.113.188   |UDP     |74    |48654  >  33480 Len=32                                  |
|53 |10.030286101|10.0.2.15        |104.17.113.188   |UDP     |74    |54646  >  33481 Len=32                                  |
|54 |10.030318418|10.0.2.15        |104.17.113.188   |UDP     |74    |59524  >  33482 Len=32                                  |
|55 |10.030396532|10.0.2.15        |104.17.113.188   |UDP     |74    |44288  >  33483 Len=32                                  |
|56 |10.030439104|10.0.2.15        |104.17.113.188   |UDP     |74    |39093  >  33484 Len=32                                  |
|57 |15.039524337|10.0.2.15        |104.17.113.188   |UDP     |74    |47572  >  33485 Len=32                                  |
|58 |15.039644459|10.0.2.15        |104.17.113.188   |UDP     |74    |35097  >  33486 Len=32                                  |
|59 |15.039690927|10.0.2.15        |104.17.113.188   |UDP     |74    |59816  >  33487 Len=32                                  |
|60 |15.039732695|10.0.2.15        |104.17.113.188   |UDP     |74    |43273  >  33488 Len=32                                  |
|61 |15.039765992|10.0.2.15        |104.17.113.188   |UDP     |74    |44101  >  33489 Len=32                                  |
|62 |15.039797062|10.0.2.15        |104.17.113.188   |UDP     |74    |34627  >  33490 Len=32                                  |
|63 |15.039832807|10.0.2.15        |104.17.113.188   |UDP     |74    |55300  >  33491 Len=32                                  |
|64 |15.039865188|10.0.2.15        |104.17.113.188   |UDP     |74    |59876  >  33492 Len=32                                  |
|65 |15.039901332|10.0.2.15        |104.17.113.188   |UDP     |74    |37206  >  33493 Len=32                                  |
|66 |15.039947517|10.0.2.15        |104.17.113.188   |UDP     |74    |42373  >  33494 Len=32                                  |
|67 |15.039984741|10.0.2.15        |104.17.113.188   |UDP     |74    |42458  >  33495 Len=32                                  |
|68 |15.040030589|10.0.2.15        |104.17.113.188   |UDP     |74    |59240  >  33496 Len=32                                  |
|69 |15.040091061|10.0.2.15        |104.17.113.188   |UDP     |74    |34726  >  33497 Len=32                                  |
|70 |15.040138006|10.0.2.15        |104.17.113.188   |UDP     |74    |42171  >  33498 Len=32                                  |
|71 |15.040179391|10.0.2.15        |104.17.113.188   |UDP     |74    |38383  >  33499 Len=32                                  |
|72 |15.040233335|10.0.2.15        |104.17.113.188   |UDP     |74    |58699  >  33500 Len=32                                  |
|73 |20.046414262|10.0.2.15        |104.17.113.188   |UDP     |74    |54162  >  33501 Len=32                                  |
|74 |20.046467113|10.0.2.15        |104.17.113.188   |UDP     |74    |47003  >  33502 Len=32                                  |
|75 |20.046493324|10.0.2.15        |104.17.113.188   |UDP     |74    |52538  >  33503 Len=32                                  |
|76 |20.046518599|10.0.2.15        |104.17.113.188   |UDP     |74    |46419  >  33504 Len=32                                  |
|77 |20.046541045|10.0.2.15        |104.17.113.188   |UDP     |74    |37538  >  33505 Len=32                                  |
|78 |20.046567233|10.0.2.15        |104.17.113.188   |UDP     |74    |43642  >  33506 Len=32                                  |
|79 |20.046609894|10.0.2.15        |104.17.113.188   |UDP     |74    |51103  >  33507 Len=32                                  |
|80 |20.046661866|10.0.2.15        |104.17.113.188   |UDP     |74    |49790  >  33508 Len=32                                  |
|81 |20.046690403|10.0.2.15        |104.17.113.188   |UDP     |74    |54030  >  33509 Len=32                                  |
|82 |20.046723264|10.0.2.15        |104.17.113.188   |UDP     |74    |47713  >  33510 Len=32                                  |
|83 |20.046749321|10.0.2.15        |104.17.113.188   |UDP     |74    |59418  >  33511 Len=32                                  |
|84 |20.046780977|10.0.2.15        |104.17.113.188   |UDP     |74    |38520  >  33512 Len=32                                  |
|85 |20.046806451|10.0.2.15        |104.17.113.188   |UDP     |74    |39747  >  33513 Len=32                                  |
|86 |20.046830841|10.0.2.15        |104.17.113.188   |UDP     |74    |52881  >  33514 Len=32                                  |
|87 |20.046853506|10.0.2.15        |104.17.113.188   |UDP     |74    |52517  >  33515 Len=32                                  |
|88 |20.046877582|10.0.2.15        |104.17.113.188   |UDP     |74    |48214  >  33516 Len=32                                  |

### EXP 4

#### Question 8

|No.|Time        |Source           |Destination                   |Protocol|Length|Info                                                                |
|---|------------|-----------------|------------------------------|--------|------|--------------------------------------------------------------------|
|1  |0.000000000 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|2  |2.004878567 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|3  |4.013909404 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|4  |6.014704775 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|5  |7.390371150 |Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|6  |8.019540738 |Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|7  |10.024435997|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|8  |12.029320850|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|9  |14.038320189|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|10 |16.039086296|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|11 |17.398028559|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|12 |18.044086528|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|13 |18.210751234|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=1/256, ttl=64 (reply in 14)     |
|14 |18.210915922|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=1/256, ttl=64 (request in 13)   |
|15 |19.220542058|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=2/512, ttl=64 (reply in 16)     |
|16 |19.220704721|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=2/512, ttl=64 (request in 15)   |
|17 |20.048876605|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|18 |20.244541551|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=3/768, ttl=64 (reply in 19)     |
|19 |20.244668454|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=3/768, ttl=64 (request in 18)   |
|20 |21.268541462|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=4/1024, ttl=64 (reply in 21)    |
|21 |21.268676188|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=4/1024, ttl=64 (request in 20)  |
|22 |22.053782201|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|23 |22.292540884|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=5/1280, ttl=64 (reply in 24)    |
|24 |22.292668696|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=5/1280, ttl=64 (request in 23)  |
|25 |23.288466177|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |Who has 172.16.40.1? Tell 172.16.40.254                             |
|26 |23.288485244|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |172.16.40.1 is at 00:21:5a:61:2f:13                                 |
|27 |23.316533602|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=6/1536, ttl=64 (reply in 28)    |
|28 |23.316657991|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=6/1536, ttl=64 (request in 27)  |
|29 |24.062789152|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|30 |24.340539589|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=7/1792, ttl=64 (reply in 31)    |
|31 |24.340695687|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=7/1792, ttl=64 (request in 30)  |
|32 |24.468507486|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |Who has 172.16.40.254? Tell 172.16.40.1                             |
|33 |24.468623843|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |172.16.40.254 is at 00:21:5a:c3:78:76                               |
|34 |24.889495253|Cisco_7c:8f:83   |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/3                        |
|35 |25.364537196|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=8/2048, ttl=64 (reply in 36)    |
|36 |25.364676322|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=8/2048, ttl=64 (request in 35)  |
|37 |26.063674969|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|38 |26.388535780|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=9/2304, ttl=64 (reply in 39)    |
|39 |26.388674976|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=9/2304, ttl=64 (request in 38)  |
|40 |27.397287629|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|41 |27.412538625|172.16.40.1      |172.16.40.254                 |ICMP    |98    |Echo (ping) request  id=0x779c, seq=10/2560, ttl=64 (reply in 42)   |
|42 |27.412667414|172.16.40.254    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x779c, seq=10/2560, ttl=64 (request in 41) |
|43 |28.068417134|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|44 |30.073516472|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|45 |32.078217221|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|46 |34.087199518|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|47 |36.002850230|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=1/256, ttl=64 (reply in 48)     |
|48 |36.003011426|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=1/256, ttl=64 (request in 47)   |
|49 |36.087965555|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|50 |37.012539643|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=2/512, ttl=64 (reply in 51)     |
|51 |37.012672554|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=2/512, ttl=64 (request in 50)   |
|52 |37.404936378|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|53 |38.036561206|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=3/768, ttl=64 (reply in 54)     |
|54 |38.036696979|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=3/768, ttl=64 (request in 53)   |
|55 |38.092864585|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|56 |39.060555320|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=4/1024, ttl=64 (reply in 57)    |
|57 |39.060718751|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=4/1024, ttl=64 (request in 56)  |
|58 |40.084558793|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=5/1280, ttl=64 (reply in 59)    |
|59 |40.084691843|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=5/1280, ttl=64 (request in 58)  |
|60 |40.097968604|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|61 |41.108547600|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=6/1536, ttl=64 (reply in 62)    |
|62 |41.108685469|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=6/1536, ttl=64 (request in 61)  |
|63 |42.102759728|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|64 |42.132543251|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=7/1792, ttl=64 (reply in 65)    |
|65 |42.132675672|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=7/1792, ttl=64 (request in 64)  |
|66 |43.156544210|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=8/2048, ttl=64 (reply in 67)    |
|67 |43.156684034|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=8/2048, ttl=64 (request in 66)  |
|68 |44.111787422|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|69 |44.180553270|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=9/2304, ttl=64 (reply in 70)    |
|70 |44.180710974|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=9/2304, ttl=64 (request in 69)  |
|71 |45.204544730|172.16.40.1      |172.16.41.253                 |ICMP    |98    |Echo (ping) request  id=0x77a9, seq=10/2560, ttl=64 (reply in 72)   |
|72 |45.204685812|172.16.41.253    |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77a9, seq=10/2560, ttl=64 (request in 71) |
|73 |46.112424600|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|74 |47.412595672|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|75 |48.117293948|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|76 |50.122237259|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|77 |52.127071197|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|78 |52.298954736|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=1/256, ttl=64 (reply in 79)     |
|79 |52.299254500|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=1/256, ttl=63 (request in 78)   |
|80 |53.300543339|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=2/512, ttl=64 (reply in 81)     |
|81 |53.300812582|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=2/512, ttl=63 (request in 80)   |
|82 |54.136052586|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|83 |54.324539828|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=3/768, ttl=64 (reply in 84)     |
|84 |54.324798105|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=3/768, ttl=63 (request in 83)   |
|85 |55.348544489|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=4/1024, ttl=64 (reply in 86)    |
|86 |55.348784747|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=4/1024, ttl=63 (request in 85)  |
|87 |56.136846280|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|88 |56.372547892|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=5/1280, ttl=64 (reply in 89)    |
|89 |56.372779070|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=5/1280, ttl=63 (request in 88)  |
|90 |57.396545918|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=6/1536, ttl=64 (reply in 91)    |
|91 |57.396780099|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=6/1536, ttl=63 (request in 90)  |
|92 |57.420248612|Cisco_7c:8f:83   |Cisco_7c:8f:83                |LOOP    |60    |Reply                                                               |
|93 |58.141746429|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|94 |58.420556934|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=7/1792, ttl=64 (reply in 95)    |
|95 |58.420819402|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=7/1792, ttl=63 (request in 94)  |
|96 |59.444541270|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=8/2048, ttl=64 (reply in 97)    |
|97 |59.444805763|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=8/2048, ttl=63 (request in 96)  |
|98 |60.146623319|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|99 |60.468548934|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=9/2304, ttl=64 (reply in 100)   |
|100|60.468784303|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=9/2304, ttl=63 (request in 99)  |
|101|61.492553036|172.16.40.1      |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x77b3, seq=10/2560, ttl=64 (reply in 102)  |
|102|61.492792455|172.16.41.1      |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x77b3, seq=10/2560, ttl=63 (request in 101)|
|103|62.151646670|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |
|104|63.480478688|HewlettP_c3:78:76|HewlettP_61:2f:13             |ARP     |60    |Who has 172.16.40.1? Tell 172.16.40.254                             |
|105|63.480500199|HewlettP_61:2f:13|HewlettP_c3:78:76             |ARP     |42    |172.16.40.1 is at 00:21:5a:61:2f:13                                 |
|106|64.160432081|Cisco_7c:8f:83   |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8003    |

#### Question 11

|No.|Time         |Source                  |Destination                   |Protocol|Length|Info                                                                                                                                                                                                                                                                                         |
|---|-------------|------------------------|------------------------------|--------|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1  |0.000000000  |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|2  |0.936570666  |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|3  |0.829331593  |172.16.41.253           |224.0.0.251                   |MDNS    |160   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|4  |2.005153167  |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|5  |2.109036718  |fe80::2c0:dfff:fe02:5595|ff02::fb                      |MDNS    |180   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|6  |2.936416038  |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|7  |4.102171673  |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|8  |4.009775262  |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|9  |4.085435405  |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|10 |4.942304774  |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|11 |6.014685451  |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|12 |6.945969554  |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|13 |8.023523163  |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|14 |8.951873375  |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|15 |10.024410916 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|16 |10.961729023 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|17 |12.029330255 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|18 |12.961462789 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|19 |14.034193162 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|20 |14.105921731 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|21 |14.093053970 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|22 |14.967361861 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|23 |16.039072132 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|24 |16.970991162 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|25 |18.048115876 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|26 |18.977020487 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|27 |20.048931971 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|28 |20.984681235 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|29 |22.053731043 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|30 |22.986522670 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|31 |23.589270951 |Cisco_7c:8f:81          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/1                                                                                                                                                                                                                                                 |
|32 |24.109071504 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|33 |24.058626566 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|34 |24.100714510 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|35 |24.990560193 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|36 |26.063762203 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|37 |26.996342280 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|38 |28.072452690 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|39 |29.000208762 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|40 |30.073323052 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|41 |31.010155623 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|42 |31.482979555 |Cisco_7c:8f:84          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/4                                                                                                                                                                                                                                                 |
|43 |32.078251191 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|44 |33.009876468 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|45 |34.083144549 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|46 |34.113045264 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|47 |34.116705853 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|48 |35.015671686 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|49 |36.087978542 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|50 |36.833009092 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|51 |37.019606193 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|52 |37.858521752 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|53 |38.096905720 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|54 |38.882512361 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|55 |39.025880662 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|56 |40.097713644 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|57 |41.033637930 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|58 |41.838068883 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|59 |42.102658475 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|60 |43.035544736 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|61 |42.850514035 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|62 |43.874514701 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|63 |44.107546246 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|64 |44.108001401 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|65 |44.124396704 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|66 |45.038850393 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|67 |46.112483394 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|68 |46.801056025 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|69 |47.044049166 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|70 |47.810508340 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|71 |48.121366573 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|72 |48.834507400 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.1? Tell 172.16.2.42                                                                                                                                                                                                                                                         |
|73 |49.048850543 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|74 |50.122182668 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|75 |51.057608008 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|76 |51.804013104 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|77 |52.127134343 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|78 |53.058381081 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|79 |52.834505515 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|80 |53.858503806 |HewlettP_19:02:ba       |Broadcast                     |ARP     |60    |Who has 172.16.2.254? Tell 172.16.2.42                                                                                                                                                                                                                                                       |
|81 |54.123666726 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|82 |54.119401870 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|83 |54.131997460 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|84 |55.063575315 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|85 |56.136838088 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|86 |57.068345193 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|87 |58.146109374 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|88 |59.073045091 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|89 |60.146697438 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|90 |61.082095190 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|91 |62.151504332 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|92 |63.082941387 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|93 |64.122985706 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|94 |64.131339697 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|95 |64.156548617 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|96 |65.087791514 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|97 |66.161318007 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|98 |67.092681728 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|99 |68.170203350 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|100|69.097593594 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|101|70.171067078 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|102|71.106455471 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|103|72.175937947 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|104|73.107293707 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|105|74.138983126 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|106|74.130668525 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|107|74.181070441 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|108|75.112155706 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|109|76.185727945 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|110|77.117204460 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|111|78.194773504 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|112|79.121990751 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|113|80.195483860 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|114|81.131067111 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|115|82.200372120 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|116|83.131692051 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|117|83.593243745 |Cisco_7c:8f:81          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/1                                                                                                                                                                                                                                                 |
|118|84.151159392 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|119|84.130022426 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|120|84.205267154 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|121|85.136711612 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|122|86.210174829 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|123|87.141547560 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|124|88.219123589 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|125|89.146365699 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|126|90.220019513 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|127|91.155313481 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|128|91.491024024 |Cisco_7c:8f:84          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/4                                                                                                                                                                                                                                                 |
|129|92.224813486 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|130|93.156295449 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|131|94.137568566 |Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|132|94.146022710 |Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|133|94.229720184 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|134|95.161093753 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|135|96.234588818 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|136|97.166027689 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|137|98.243607000 |Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|138|99.170799732 |Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|139|100.244346270|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|140|101.179862473|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|141|102.249357170|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|142|103.180553553|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|143|104.158009286|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|144|104.145215627|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|145|104.254119715|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|146|105.185540847|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|147|105.090506322|fe80::222:64ff:fe19:2ba |ff02::2                       |ICMPv6  |70    |Router Solicitation from 00:22:64:19:02:ba                                                                                                                                                                                                                                                   |
|148|106.259023130|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|149|107.190634230|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|150|108.267979503|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|151|109.195431975|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|152|110.268805236|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|153|110.735761246|172.16.41.1             |224.0.0.251                   |MDNS    |160   |Standard query 0x0000 PTR _nfs._tcp.local, "QM" question PTR _ftp._tcp.local, "QM" question PTR _webdav._tcp.local, "QM" question PTR _webdavs._tcp.local, "QM" question PTR _sftp-ssh._tcp.local, "QM" question PTR _smb._tcp.local, "QM" question PTR _afpovertcp._tcp.local, "QM" question|
|154|111.204572798|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|155|112.273680715|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|156|113.204991497|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|157|114.152886573|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|158|114.161233440|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|159|114.278579450|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|160|115.209979001|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|161|116.283458630|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|162|117.214866003|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|163|118.292438679|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|164|119.219658859|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|165|120.293235428|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|166|121.228741854|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|167|122.298105459|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|168|123.229521492|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|169|124.168900336|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|170|124.152144442|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|171|124.302975979|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|172|125.234708323|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|173|126.307937641|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|174|127.239207497|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|175|128.316843868|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|176|129.244398308|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|177|130.317660452|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|178|131.253072243|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|179|132.322553670|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|180|133.253994986|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|181|134.159865814|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|182|134.168226929|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|183|134.327448914|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|184|135.258835823|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|185|136.332323764|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|186|137.263715073|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|187|138.341362130|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|188|139.268530837|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|189|140.342244574|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|190|141.277660276|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|191|142.347004535|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|192|143.278302467|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|193|143.597206412|Cisco_7c:8f:81          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/1                                                                                                                                                                                                                                                 |
|194|144.175871475|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|195|144.159147499|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|196|144.351858363|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|197|145.283314275|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|198|146.356746972|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|199|147.288075633|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|200|148.365790157|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|201|149.293070750|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|202|150.297254171|HewlettP_61:2f:13       |Broadcast                     |ARP     |60    |Who has 172.16.40.254? Tell 172.16.40.1                                                                                                                                                                                                                                                      |
|203|150.297414806|KYE_02:55:95            |Broadcast                     |ARP     |42    |Who has 172.16.41.1? Tell 172.16.41.253                                                                                                                                                                                                                                                      |
|204|150.297531231|HewlettP_19:02:ba       |KYE_02:55:95                  |ARP     |60    |172.16.41.1 is at 00:22:64:19:02:ba                                                                                                                                                                                                                                                          |
|205|150.297280222|HewlettP_c3:78:76       |HewlettP_61:2f:13             |ARP     |42    |172.16.40.254 is at 00:21:5a:c3:78:76                                                                                                                                                                                                                                                        |
|206|150.297538425|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=1/256, ttl=63 (no response found!)                                                                                                                                                                                                                       |
|207|150.297401187|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=1/256, ttl=64 (reply in 208)                                                                                                                                                                                                                             |
|208|150.297641161|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=1/256, ttl=64 (request in 207)                                                                                                                                                                                                                           |
|209|150.297647377|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=1/256, ttl=63                                                                                                                                                                                                                                            |
|210|150.366570913|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|211|151.302024747|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|212|151.313127271|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=2/512, ttl=63 (reply in 213)                                                                                                                                                                                                                             |
|213|151.313230846|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=2/512, ttl=64 (request in 212)                                                                                                                                                                                                                           |
|214|151.313111278|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=2/512, ttl=64 (reply in 215)                                                                                                                                                                                                                             |
|215|151.313239716|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=2/512, ttl=63 (request in 214)                                                                                                                                                                                                                           |
|216|151.490955035|Cisco_7c:8f:84          |CDP/VTP/DTP/PAgP/UDLD         |CDP     |601   |Device ID: gnu-sw4  Port ID: FastEthernet0/4                                                                                                                                                                                                                                                 |
|217|152.337121442|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=3/768, ttl=63 (no response found!)                                                                                                                                                                                                                       |
|218|152.337101677|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=3/768, ttl=64 (reply in 219)                                                                                                                                                                                                                             |
|219|152.337232909|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=3/768, ttl=64 (request in 218)                                                                                                                                                                                                                           |
|220|152.337241918|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=3/768, ttl=63                                                                                                                                                                                                                                            |
|221|152.371411121|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|222|153.302965440|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|223|153.361097245|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=4/1024, ttl=63 (no response found!)                                                                                                                                                                                                                      |
|224|153.361082509|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=4/1024, ttl=64 (reply in 225)                                                                                                                                                                                                                            |
|225|153.361200051|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=4/1024, ttl=64 (request in 224)                                                                                                                                                                                                                          |
|226|153.361207524|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=4/1024, ttl=63                                                                                                                                                                                                                                           |
|227|154.166738127|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|228|154.175161401|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|229|154.376279476|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|230|154.385107759|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=5/1280, ttl=63 (reply in 231)                                                                                                                                                                                                                            |
|231|154.385245486|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=5/1280, ttl=64 (request in 230)                                                                                                                                                                                                                          |
|232|154.385092045|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=5/1280, ttl=64 (reply in 233)                                                                                                                                                                                                                            |
|233|154.385252889|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=5/1280, ttl=63 (request in 232)                                                                                                                                                                                                                          |
|234|155.307707731|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|235|155.409142647|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=6/1536, ttl=64 (no response found!)                                                                                                                                                                                                                      |
|236|155.409159339|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=6/1536, ttl=63 (reply in 237)                                                                                                                                                                                                                            |
|237|155.409274717|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=6/1536, ttl=63 (request in 236)                                                                                                                                                                                                                          |
|238|155.409266127|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=6/1536, ttl=64                                                                                                                                                                                                                                           |
|239|155.444998516|HewlettP_c3:78:76       |HewlettP_61:2f:13             |ARP     |42    |Who has 172.16.40.1? Tell 172.16.40.254                                                                                                                                                                                                                                                      |
|240|155.522469084|HewlettP_19:02:ba       |KYE_02:55:95                  |ARP     |60    |Who has 172.16.41.253? Tell 172.16.41.1                                                                                                                                                                                                                                                      |
|241|155.445129888|HewlettP_61:2f:13       |HewlettP_c3:78:76             |ARP     |60    |172.16.40.1 is at 00:21:5a:61:2f:13                                                                                                                                                                                                                                                          |
|242|155.522476557|KYE_02:55:95            |HewlettP_19:02:ba             |ARP     |42    |172.16.41.253 is at 00:c0:df:02:55:95                                                                                                                                                                                                                                                        |
|243|156.433121314|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=7/1792, ttl=64 (no response found!)                                                                                                                                                                                                                      |
|244|156.381195672|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|245|156.433136469|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=7/1792, ttl=63 (reply in 246)                                                                                                                                                                                                                            |
|246|156.433242768|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=7/1792, ttl=64 (request in 245)                                                                                                                                                                                                                          |
|247|156.433250241|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=7/1792, ttl=63                                                                                                                                                                                                                                           |
|248|157.312650885|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|249|157.457125612|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=8/2048, ttl=63 (no response found!)                                                                                                                                                                                                                      |
|250|157.457109199|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=8/2048, ttl=64 (reply in 251)                                                                                                                                                                                                                            |
|251|157.457234773|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=8/2048, ttl=64 (request in 250)                                                                                                                                                                                                                          |
|252|157.457243434|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=8/2048, ttl=63                                                                                                                                                                                                                                           |
|253|158.390226914|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|254|158.481114125|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=9/2304, ttl=64 (reply in 255)                                                                                                                                                                                                                            |
|255|158.481243681|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=9/2304, ttl=63 (request in 254)                                                                                                                                                                                                                          |
|256|158.481129840|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=9/2304, ttl=63 (reply in 257)                                                                                                                                                                                                                            |
|257|158.481236837|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=9/2304, ttl=64 (request in 256)                                                                                                                                                                                                                          |
|258|159.317391570|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|259|159.505108716|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=10/2560, ttl=64 (no response found!)                                                                                                                                                                                                                     |
|260|159.505124919|172.16.40.1             |172.16.41.1                   |ICMP    |98    |Echo (ping) request  id=0x7859, seq=10/2560, ttl=63 (reply in 261)                                                                                                                                                                                                                           |
|261|159.505271166|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=10/2560, ttl=63 (request in 260)                                                                                                                                                                                                                         |
|262|159.505263135|172.16.41.1             |172.16.40.1                   |ICMP    |98    |Echo (ping) reply    id=0x7859, seq=10/2560, ttl=64                                                                                                                                                                                                                                          |
|263|160.390962552|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|264|161.326845562|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|265|162.395891459|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|266|163.327164248|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|267|164.182719065|Cisco_7c:8f:84          |Cisco_7c:8f:84                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|268|164.178558133|Cisco_7c:8f:81          |Cisco_7c:8f:81                |LOOP    |60    |Reply                                                                                                                                                                                                                                                                                        |
|269|164.400723496|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|270|165.332241218|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|271|166.405943362|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|272|167.337549014|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|273|168.414564427|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
|274|169.342050772|Cisco_7c:8f:84          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/40/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8004                                                                                                                                                                                                                             |
|275|170.415454624|Cisco_7c:8f:81          |Spanning-tree-(for-bridges)_00|STP     |60    |Conf. Root = 32768/41/00:1e:14:7c:8f:80  Cost = 0  Port = 0x8001                                                                                                                                                                                                                             |
