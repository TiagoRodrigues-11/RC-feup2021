
#include "llapi.h"

struct termios oldtio,newtio;

char llwrite_start = 0;
char llread_start = 1;

int llopen(int port, int state) {
    if (state != RECEIVER && state != TRANSMITER) return 1;

    char serial[256];
    snprintf(serial, 256, "/dev/ttyS%d", port);


    int fd = open(serial, O_RDWR | O_NOCTTY );
    if (fd < 0) { perror(serial); return(-1); }

    /*
    Open serial port device for reading and writing and not as controlling tty
    because we don't want to get killed if linenoise sends CTRL-C.
    */

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

    if (tcsetattr(fd,TCSANOW, &newtio) == -1) {
        perror("tcsetattr");
        exit(-1);
    }

    unsigned char message[5] = {FLAG, ADDR, SET, SET ^ ADDR, FLAG};

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

        if ((message[ICTRL] ^ message[IADDR]) != message[IBCC1]) {
            printf("Parity error\n");
            return -1;
        }
    }

    else if (state == RECEIVER) {
        alarm_flag = 0;
        read_message(fd, message);
        if ((message[ICTRL] ^ message[IADDR]) != message[IBCC1]) {
            printf("Parity error\n");
            return -1;
        }

        message[ICTRL] = UA;
        message[IBCC1] = message[ICTRL] ^ message[IADDR];

        write(fd, message, 5);
    }

    alarm(0);
    return fd;
}

int llclose(int fd) {
    tcsetattr(fd,TCSANOW,&oldtio);
    close(fd);
}

int llread(int fd, char* buffer) {
    char *trama = (char *)malloc(sizeof(char)* 1024);
	char *stuffed = (char *)malloc(sizeof(char)* 1024);
    char *destuffed = (char *)malloc(sizeof(char)* 1024);
	int stuffed_size = 0, destuffed_size = 0, trama_index = 0;

    while (true)
    {
        while(true) {
            int res = read(fd, trama + trama_index, 1);
            
            if( trama[trama_index] != FLAG && trama_index == 0) continue;

            if( trama[trama_index] == FLAG && trama_index != 0) break;

            trama_index++;
        }

        // Check BCC1
        
        if ((trama[ICTRL] ^ trama[IADDR]) != trama[IBCC1]) {
            continue;
        }

        // Get stuffed data

        memcpy(stuffed, (trama + 4), trama_index - 4);

        stuffed_size = trama_index - 5;

        // Byte Destuffing 

        for (int i = 0, j = 1; i < stuffed_size; i++, j++) {
            if (j == stuffed_size) destuffed[destuffed_size] = stuffed[i];
            else if (stuffed[i] == 0x7D && stuffed[j] == 0x5D) {
                destuffed[destuffed_size] = 0x7D;
                i++; j++;
            }
            else if (stuffed[i] == 0x7D && stuffed[j] == 0x5E) {
                destuffed[destuffed_size] = 0x7E;
                i++; j++;
            }
            else
                destuffed[destuffed_size] = stuffed[i];
            destuffed_size++;
        }

        // Check BCC2
        char xordata = destuffed[0];

        for(int i = 1; i < destuffed_size - 1; i++) {
            xordata = xordata ^ destuffed[i];
        }


        if (xordata != destuffed[destuffed_size - 1]) {
            unsigned char temp = REJ(llread_start);
            unsigned char msg[5] = {FLAG, ADDR, temp, ADDR ^ temp, FLAG};

            write(fd, msg, 5);
            continue;
        } else {
            unsigned char temp = RR(llread_start);
            unsigned char msg[5] = {FLAG, ADDR, temp, ADDR ^ temp, FLAG};
            
            write(fd, msg, 5);
            llread_start = llread_start ? 0 : 1;
            break;
        }
    }

    memcpy(buffer, destuffed, (destuffed_size-2) * sizeof(char));
    
	free(destuffed);
    free(stuffed);
    free(trama);

    return destuffed_size -2;
}

int llwrite(int fd, char* buffer, int length) {
    char *unstuffed = (char *)malloc(sizeof(char)* 1024);
    char *stuffed = (char *)malloc(sizeof(char)* 1024);
    char *trama = (char *)malloc(sizeof(char)* 1024);
    int stuffed_index = 0;

    // Fill Unstuffed

    for (int i = 0; i < length; i++) unstuffed[i] = buffer[i];
    
    // BCC2

    char bcc2 = buffer[0];
    for (int i = 1; i < length; i++) {
        bcc2 ^= buffer[i];
    }

    unstuffed[length] = bcc2;

    // Stuff
    for (int i = 0; i < length + 1; i++, stuffed_index++) {
        if (unstuffed[i] == 0x7E) {
            stuffed[stuffed_index++] = 0x7D;
            stuffed[stuffed_index] = 0x5E;
        }
        else if (unstuffed[i] == 0x7D) {
            stuffed[stuffed_index++] = 0x7D;
            stuffed[stuffed_index] = 0x5D;
        }
        else {
            stuffed[stuffed_index] = unstuffed[i];
        }
    }

    // Setup Trama
    char temp_C = 0x00;
    trama[0] = FLAG;
    trama[1] = ADDR;
    trama[2] = temp_C;
    trama[3] = ADDR ^ temp_C;
    memcpy(trama + 4 * sizeof(char), stuffed, (stuffed_index + 1) * sizeof(char));
    trama[5 + stuffed_index] = FLAG;

    unsigned char ans[5];
    int tries = 0;

    // ACK handling
    while (tries < 3) {
        int temp = write(fd, trama, stuffed_index + 6);
        read_message(fd, ans);
        unsigned char t = (ans[IADDR] ^ ans[ICTRL]);

        if (t != ans[IBCC1]) {
            tries++;
            continue;
        }

        t = REJ(llwrite_start ? 0 : 1);

        if (ans[ICTRL] == t) {
            tries++;
            continue;
        }

        t = RR(llwrite_start ? 0 : 1);

        if (ans[ICTRL] == t) {
            llwrite_start = llwrite_start ? 0 : 1;
            break;
        }

        tries++;
    }

    free(trama);
    free(unstuffed);
    free(stuffed);

    return tries >= 3 ? -1 : stuffed_index + 6;

}


// Estabelecer ligaçao
int read_message(int fd, unsigned char * message) {
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
