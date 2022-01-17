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