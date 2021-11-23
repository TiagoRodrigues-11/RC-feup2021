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

#include "llapi.h"

#define BAUDRATE B38400
#define _POSIX_SOURCE 1 /* POSIX compliant source */
#define FALSE 0
#define TRUE 1
#define PACKET_SIZE 256
#define WAITING 0
#define WRITING 1
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

void extract_filename(char * packet, char * filename) {
    int size = packet[1];

    for (int i = 0; i < size; i++) {
        filename[i] = packet[2 + i];
    }
}

int make_start_packet(char * filename, char * packet) {
    char size = (char) (strlen(filename) + 1);
    packet[C] = START;
    packet[1] = size;
    memcpy(packet + 2, filename, size);

    return size + 2;
}

int transmit(int fd, char * filename) {
    int fd_file;
    struct stat file_stat;
    char packet[1024];
    int size = make_start_packet(filename, packet), n = 0;
    char msg[256];

    printf("%s\n", filename);

    if((fd_file = open(filename, O_RDWR)) < 0) perror("Error opening file: ");

    printf("Writing file. Packet size: %d\n", PACKET_SIZE);

    // START
    llwrite(fd, packet, size);

    // DATA
    char read_data[PACKET_SIZE];
    int read_size;

    while (true)
    {
        if (true) {
            read_size = 0;

            for (; read_size < PACKET_SIZE; read_size++) {
                if (read(fd_file, read_data + read_size, 1) == 0) break;
            }

            printf("read_size: %d\n",read_size);

            if (read_size == 0) {
                printf("File over.\n");
                break;
            }

            packet[C] = DATA;
            packet[N] = 0;
            packet[L2] = (unsigned char) (read_size / 256);
            packet[L1] = (unsigned char) (read_size % 256);

            memcpy(packet + D, read_data, read_size);

            printf("Last packet: 0x%02x\n", packet[read_size + 3]);
        }

        llwrite(fd, packet, read_size + 5);
    }
    

    // END
    size = make_start_packet(filename, packet);
    packet[C] = END;

    llwrite(fd, packet, size);

    printf("Finished writing file\n");

    close(fd_file);

    return 0;
}

int receive(int fd) {
    int fd_file, status = WAITING;

    while (true) {
        char packet[1024];
        int bytes_read = llread(fd, packet);

        printf("llread executed C=%d\n\n", packet[C]);

        if (status == WAITING && packet[C] == START) {
            char filename[256];

            extract_filename(packet, filename);

            unlink(filename);

            if((fd_file = open(filename, O_RDWR | O_CREAT, 0777)) < 0) perror("Error creating new file: ");

            status = WRITING;
        }

        else if (status == WRITING && packet[C] == END) {
            printf("Closed\n");
            close(fd_file);
            return 0;
        }

        else if (status == WRITING && packet[C] == DATA) {
            unsigned char l2 = packet[L2], l1 = packet[L1];
            int res = l2 * 256 + l1;
            write(fd_file, packet + 4, res);
        }

        else {
            printf("Catastrophe!\n");
            close(fd_file);
            return -1;
        }
    }
}

int main(int argc, char** argv)
{
    int fd,c, res;
    struct termios oldtio,newtio;
    char buf[255];

    int state = strcmp(argv[1], "T") == 0 ? TRANSMITER : RECEIVER;

    if ( (argc < 3 && state == RECEIVER) || (argc < 4 && state == TRANSMITER) ||
         ((strcmp("/dev/ttyS10", argv[2])!=0) &&
          (strcmp("/dev/ttyS11", argv[2])!=0) &&
          (strcmp("/dev/ttyS1", argv[2])!=0) &&
          (strcmp("/dev/ttyS0", argv[2])!=0))) {
        printf("Usage:\tnserial SerialPort\n\tex: nserial /dev/ttyS1\n");
        exit(1);
    }


    /*
    Open serial port device for reading and writing and not as controlling tty
    because we don't want to get killed if linenoise sends CTRL-C.
    */


    fd = open(argv[2], O_RDWR | O_NOCTTY );
    if (fd < 0) { perror(argv[2]); exit(-1); }

    if (tcgetattr(fd,&oldtio) == -1) { /* save current port settings */
        perror("tcgetattr");
        exit(-1);
    }

    bzero(&newtio, sizeof(newtio));
    newtio.c_cflag = BAUDRATE | CS8 | CLOCAL | CREAD;
    newtio.c_iflag = IGNPAR;
    newtio.c_oflag = 0;

    /* set input mode (non-canonical, no echo,...) */
    newtio.c_lflag = 0;

    newtio.c_cc[VTIME]    = 100;   /* inter-character timer unused */
    newtio.c_cc[VMIN]     = 0;   /* blocking read until 5 chars received */

    /*
    VTIME e VMIN devem ser alterados de forma a proteger com um temporizador a
    leitura do(s) próximo(s) caracter(es)
    */


    tcflush(fd, TCIOFLUSH);

    if (tcsetattr(fd,TCSANOW,&newtio) == -1) {
        perror("tcsetattr");
        exit(-1);
    }

    printf("New termios structure set\n");

    // Establish connection
       
    llopen(fd, state);

    printf("Establish connection\n");

    if(state == TRANSMITER) {
        transmit(fd, argv[3]);
    } else {
        receive(fd);
    }

    /*
    O ciclo WHILE deve ser alterado de modo a respeitar o indicado no guião
    */

    tcsetattr(fd,TCSANOW,&oldtio);
    close(fd);
    return 0;
}
// End of file