/*Non-Canonical Input Processing*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

#define BAUDRATE B38400
#define _POSIX_SOURCE 1 /* POSIX compliant source */
#define FALSE 0
#define TRUE 1
#define RECEIVER 0x00
#define TRANSMITER 0x01
#define FLAG 0x7E
#define SET 0x03
#define UA 0x07
#define ADDR_STANDIN 0x03
#define CNTRL 2
#define ADDR 1
#define PROTEC 3

volatile int STOP=FALSE;

int alarm_flag = 1, alarm_count = 0;

void atend() {
    printf("Alarm #%d\n", ++alarm_count);
    alarm_flag = 1;
}

int read_message(int fd, char * message) {
    int res, message_index = 0;
    while (alarm_flag == 0) {
        res = read(fd, message + message_index, 1);
        if (message[message_index] != FLAG && message_index == 0) continue;
        else if (message[message_index] == FLAG && message_index == 4) {
            message_index = 0;
            return 0;
        }
        else {
            message_index++;
        }
    }
    return 1;
}

int llopen(int fd, int state) {
    if (state != RECEIVER && state != TRANSMITER) return 1;

    char message[5] = {FLAG, ADDR_STANDIN, SET, SET ^ ADDR_STANDIN, FLAG};

    alarm(0);

    signal(SIGALRM, atend);

    if (state == TRANSMITER) {
        while (alarm_count < 3) {
            if (alarm_flag == 1) {
                write(fd, message, 5);
                alarm(3);
                alarm_flag = 0;
            }

            if (!read_message(fd, message)) break;
        }

        if ((message[CNTRL] ^ message[ADDR]) != message[PROTEC]) {
            printf("Parity error\n");
            return 1;
        }
    }

    else if (state == RECEIVER) {
        alarm_flag = 0;

        read_message(fd, message);

        if ((message[CNTRL] ^ message[ADDR]) != message[PROTEC]) {
            printf("Parity error\n");
            return 1;
        }

        message[CNTRL] = UA;
        message[PROTEC] = message[CNTRL] ^ message[ADDR];

        write(fd, message, 5);
    }

    alarm(0);
}

int main(int argc, char** argv)
{
    int fd,c, res;
    struct termios oldtio,newtio;
    char buf[255];

    int state = strcmp(argv[1], "T") == 0 ? TRANSMITER : RECEIVER;

    printf("%d\n", state);

    if ( (argc < 3) ||
         ((strcmp("/dev/ttyS10", argv[2])!=0) &&
          (strcmp("/dev/ttyS11", argv[2])!=0) )) {
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


    /*
    O ciclo WHILE deve ser alterado de modo a respeitar o indicado no guião
    */

    tcsetattr(fd,TCSANOW,&oldtio);
    close(fd);
    return 0;
}
