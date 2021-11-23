
#include "llapi.h"

#define RR(n) n << 7 | 0x05
#define REJ(n) n << 7 | 0x01

char llwrite_start = 0;
char llread_start = 1;

int llopen(int fd, int state) {
    if (state != RECEIVER && state != TRANSMITER) return 1;

    char message[5] = {FLAG, ADDR, SET, SET ^ ADDR, FLAG};

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

        if ((message[ICTRL] ^ message[IADDR]) != message[IBBC1]) {
            printf("Parity error\n");
            return -1;
        }
    }

    else if (state == RECEIVER) {
        alarm_flag = 0;

        read_message(fd, message);

        if ((message[ICTRL] ^ message[IADDR]) != message[IBBC1]) {
            printf("Parity error\n");
            return -1;
        }

        message[ICTRL] = UA;
        message[IBBC1] = message[ICTRL] ^ message[IADDR];

        write(fd, message, 5);
    }

    alarm(0);
    return fd;
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
        
        if ((trama[ICTRL] ^ trama[IADDR]) != trama[IBBC1]) {
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
            char msg[5] = {FLAG, ADDR, REJ(llread_start), ADDR ^ REJ(llread_start), FLAG};
            write(fd, msg, 5);
            continue;
        }

        else {
            char msg[5] = {FLAG, ADDR, RR(llread_start), ADDR ^ RR(llread_start), FLAG};
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

    char ans[5];
    int tries = 0;

    // ACK handling
    while (tries < 3) {
        int temp = write(fd, trama, stuffed_index + 6);

        read_message(fd, ans);

        if (ans[IBBC1] != ans[IADDR] ^ ans[ICTRL]) {
            printf("ACK - BCC1 bad\n");
            tries++;
            continue;
        }

        if (ans[ICTRL] == REJ(llwrite_start ? 0 : 1)) {
            printf("ACK - REJ\n");
            tries++;
            continue;
        }
        else if (ans[ICTRL] == RR(llwrite_start ? 0 : 1)) {
            printf("ACK - RR\n");
            llwrite_start = llwrite_start ? 0 : 1;
            break;
        }
    }

    free(trama);
    free(unstuffed);
    free(stuffed);

    return tries >= 3 ? -1 : stuffed_index + 6;

}


// Estabelecer ligaçao
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



// Ler dados

int read_data () {
	
	
	
}


