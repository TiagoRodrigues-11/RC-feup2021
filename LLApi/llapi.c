
#include "llapi.h"

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
	char *stuffed = (char *)malloc(sizeof(char)* 32768);
    char *destuffed = (char *)malloc(sizeof(char)* 32768);
	int stuffed_index = 0, destuffed_index = 0;

	while(true) {
		int res = read(fd, stuffed + stuffed_index, 1);
		
		if( stuffed[stuffed_index] != FLAG && stuffed_index == 0) continue;
		if( stuffed[stuffed_index] == FLAG ) 
			if( stuffed_index != 0) break;
			
		stuffed_index++;
	}
	
	// Check BCC1
	
	if ((stuffed[ICTRL] ^ stuffed[IADDR]) != stuffed[IBBC1]) {
		// Nao envia nada e voltar a ler
	}
	
    // Byte Destuffing 

    for(int i = 4, j = 5; j < stuffed_index; i++, j++, destuffed_index++) {
        if(stuffed[i] == 0x7d && stuffed[j] == 0x5e) {
            destuffed[destuffed_index] = 0x7e;
            i++; j++;
        } else if (stuffed[i] == 0x7d && stuffed[j] == 0x5d) {
            destuffed[destuffed_index] = 0x7d;
            i++;j++;
        } else {
            destuffed[destuffed_index] = stuffed[i];
        }
    }

    free(stuffed);

	// Check BCC2 

    char xordata = destuffed[4];

    for(int i = 5; i < destuffed_index; i++) {
        xordata = xordata ^ destuffed[i];
    }
	
    if (xordata != destuffed[destuffed_index]) {
		// Mandar um REJ
	}

    memcpy(buffer, destuffed, (destuffed_index + 1) * sizeof(char));

	free(destuffed);

	// Quando da certo enviar um RR


    return destuffed_index + 1;
}

int llwrite(int fd, char* buffer, int length) {
    char *stuffed = (char *)malloc(sizeof(char)* 32768);
    char *trama = (char *)malloc(sizeof(char)* 32768);
    int stuffed_index = 0;
    
    // BCC2

    char bcc2 = buffer[0];
    for(int i = 1; i < length + 1; i++) {
        bcc2 = bcc2 ^ buffer[i];
    }

    // Byte stuffing

    for(int i = 0; i < length +1; i++, stuffed_index++) {
        if(buffer[i] == 0x7e) {
            stuffed[stuffed_index++] = 0x7d;
            stuffed[stuffed_index] = 0x5e;
        } else if (buffer[i] == 0x7d) {
            stuffed[stuffed_index++] = 0x7d;
            stuffed[stuffed_index] = 0x5d;
        } else {
            stuffed[stuffed_index] = stuffed[i];
        }
    }

    // Setup Trama
    char temp_C = 0x00;
    trama[0] = FLAG;
    trama[1] = ADDR;
    trama[2] = temp_C;
    trama[3] = ADDR ^ temp_C;
    memcpy(trama + 4 * sizeof(char), stuffed, (stuffed_index + 1) * sizeof(char));
    trama[5 + stuffed_index] = bcc2;
    trama[6 + stuffed_index] = FLAG;

    write(fd, trama, stuffed_index + 7);

    return stuffed_index + 7;

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


