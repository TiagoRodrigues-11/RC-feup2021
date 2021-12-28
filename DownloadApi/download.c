#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

struct User {
    char name[256];
    char password[256];
};

void print_usage() {
    printf("Something\n");
}

int main(int argc, char ** argv) {
    if (argc < 2)
        print_usage();

    char info[256];

    strncpy(info, argv[1] + 6, strlen(argv[1]) - 5);

    char * at;

    struct User user = {"anonymous", "password"};
    char host[256] = {0};
    char path[256] = {0};

    int host_index = 0;
    int path_index = 0;
    int info_index = 0;

    if ((at = strstr(info, "@")) != NULL) {
        //DO SOMETHING
        //ALTER NDEX
    }

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

    printf("%s\n", host_struct->h_addr);

    int sockfd;
    struct sockaddr_in server_addr;
    char buf[] = "user anonymous\n";
    size_t bytes;

    /*server address handling*/
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(host_struct->h_addr);    /*32 bit Internet address network byte ordered*/
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

    bytes = write(sockfd, buf, strlen(buf));
    if (bytes > 0)
        printf("Bytes escritos %ld\n", bytes);
    else {
        perror("write()");
        exit(-1);
    }
    if (close(sockfd)<0) {
        perror("close()");
        exit(-1);
    }

    char ans[256];

    read(sockfd, ans, 256);

    printf("%s\n", ans);

    return 0;
}