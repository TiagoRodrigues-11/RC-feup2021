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

volatile int STOP=FALSE;

int alarm_flag = 1;
int alarm_count = 0;

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

    printf("Establish connection\n");

    if(state == TRANSMITER) {
        int fd_file, buffer_file_size = 0;
        char *buffer_file = (char *)malloc(sizeof(char)* 32768);

        if((fd_file = open("pinguim.gif", O_RDONLY)) < 0) 
            printf("Error on finding ...\n");

        while(read(fd_file, buffer_file, 1) > 0) 
            buffer_file_size++;

        llwrite(fd, buffer_file, buffer_file_size);
        printf("Written\n");   

        close(fd_file);
        free(buffer_file);

    } else {
        char *buffer_file = (char *)malloc(sizeof(char)* 32768);

        int buffer_size = llread(fd, buffer_file);
        int fd_file;

        if((fd_file = open("result.gif", O_RDWR | O_CREAT, 0777)) < 0) 
            printf("Error on finding ...\n");

        write(fd_file, buffer_file, buffer_size);
        
        
        close(fd_file);
        free(buffer_file);

    }

    /*
    O ciclo WHILE deve ser alterado de modo a respeitar o indicado no guião
    */

    tcsetattr(fd,TCSANOW,&oldtio);
    close(fd);
    return 0;
}
















// End of file