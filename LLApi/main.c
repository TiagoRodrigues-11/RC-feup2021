/*Non-Canonical Input Processing*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "linklayer.h"

#define _POSIX_SOURCE 1 /* POSIX compliant source */
#define FALSE 0
#define TRUE 1
#define PACKET_SIZE 256
#define WAITING 0 // Waiting for a file to be transmitted
#define WRITING 1 // Writing a file
#define DATA 0x01
#define START 0x02
#define END 0x03
#define C 0
#define N 1
#define L2 2
#define L1 3
#define D 4

volatile int STOP=FALSE;

int alarm_flag = 1;
int alarm_count = 0;

// Extract filename from a control packet
void extract_filename(char * packet, char * filename) {
    int size = packet[1];

    for (int i = 0; i < size - 1; i++) {
        filename[i] = packet[2 + i];
    }
}

// Create a start control packet
int make_start_packet(char * filename, char * packet) {
    char size = (char) (strlen(filename) + 1);
    packet[C] = START;
    packet[1] = size;
    memcpy(packet + 2, filename, size);

    return size + 2;
}

// Transmit file at filename path through serial port indicated by fd
int transmit(int fd, char * filename) {
    int fd_file;
    struct stat file_stat;
    char packet[1024];
    int size = make_start_packet(filename, packet), n = 0;
    char msg[256];

    if((fd_file = open(filename, O_RDWR)) < 0) perror("Error opening file: ");

    printf("Writing file: %s. Packet size: %d\n", filename, PACKET_SIZE);

    // START PACKET
    llwrite(fd, packet, size);

    // DATA PACKETS
    char read_data[PACKET_SIZE];
    int read_size;

    int c = 0;

    while (true)
    {
        if (true) {
            read_size = 0;

            for (; read_size < PACKET_SIZE; read_size++) {
                if (read(fd_file, read_data + read_size, 1) == 0) break;
            }


            if (read_size == 0) {
                alarm(0);
                printf("File over.\n");
                alarm(0);
                break;
            }

            packet[C] = DATA;
            packet[N] = c % 256;
            packet[L2] = (unsigned char) (read_size / 256);
            packet[L1] = (unsigned char) (read_size % 256);

            memcpy(packet + D, read_data, read_size);
        }

        if (llwrite(fd, packet, read_size + 5) < 0) return -1;
        c++;
    }
    

    // END PACKET
    size = make_start_packet(filename, packet);
    packet[C] = END;

    llwrite(fd, packet, size);
    
    alarm(0);

    printf("Finished writing file\n");

    close(fd_file);

    return 0;
}

// Receive a file through serial port indicate by file descriptor fd
int receive(int fd) {
    int fd_file, status = WAITING;

    while (true) {
        char packet[1024];
        int bytes_read = llread(fd, packet);
        
        // If state machine is waiting for file and receives start packet
        if (status == WAITING && packet[C] == START) {
            char filename[256];

            extract_filename(packet, filename);

            unlink(filename);

            if((fd_file = open(filename, O_RDWR | O_CREAT, 0777)) < 0) perror("Error creating new file: ");

            status = WRITING;
        }

        // If state machine is writing and receives an end packet
        else if (status == WRITING && packet[C] == END) {
            printf("Finished receiving\n");
            close(fd_file);
            return 0;
        }

        // If state machine is writing and receives a data packet
        else if (status == WRITING && packet[C] == DATA) {
            unsigned char l2 = packet[L2], l1 = packet[L1];
            int res = l2 * 256 + l1;
            write(fd_file, packet + 4, res);
        }

        // Otherwise
        else {
            printf("Catastrophe!\n");
            close(fd_file);
            return -1;
        }
    }
}

int main(int argc, char** argv)
{
    int fd, c, res, port;
    char buf[255];

    int state;
    if (strcmp(argv[1], "T") == 0) state = TRANSMITER;
    else if (strcmp(argv[1], "R") == 0) state = RECEIVER;
    else {
        printf("Bad arguments\n");
        exit(-1);
    }

    if ((argc < 3 && state == RECEIVER) || (argc < 4 && state == TRANSMITER)) {
        printf("Usage:\tnserial SerialPort\n\tex: nserial /dev/ttyS1\n");
        exit(1);
    }

    sscanf(argv[2], "%d", &port);

    printf("New termios structure set\n");

    // Establish connection
       
    fd = llopen(port, state);

    if (fd < 0) exit(-1);

    printf("Establish connection\n");

    if(state == TRANSMITER) {
        transmit(fd, argv[3]);
    } else {
        receive(fd);
    }

    printf("Closing\n");

    llclose(fd);

    return 0;
}
