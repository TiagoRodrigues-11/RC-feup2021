
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
    char *trama = (char *)malloc(sizeof(char)* 32768);
	char *stuffed = (char *)malloc(sizeof(char)* 32768);
    char *destuffed = (char *)malloc(sizeof(char)* 32768);
	int stuffed_size = 0, destuffed_size = 0, trama_index = 0;
    int while_counter = 0;

	while(true) {
        while_counter++;

		int res = read(fd, trama + trama_index, 1);
		
		if( trama[trama_index] != FLAG && trama_index == 0) continue;

		if( trama[trama_index] == FLAG && trama_index != 0) break;

        trama_index++;
	}

    printf("While counter: %d\n", while_counter);
	
	// Check BCC1
	
	if ((trama[ICTRL] ^ trama[IADDR]) != trama[IBBC1]) {
		// Nao envia nada e voltar a ler
        printf("BCC1 Bad\n");
	}

    // Get stuffed data

    memcpy(stuffed, trama + 4, trama_index - 4);

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

    free(stuffed);

	// Check BCC2 

    char xordata = destuffed[0];

    for(int i = 1; i < destuffed_size - 1; i++) {
        xordata = xordata ^ destuffed[i];
    }
	
    if (xordata != destuffed[destuffed_size - 1]) {
		// Mandar um REJ
        printf("BCC2 Bad\n");
	}

    memcpy(buffer, destuffed, (destuffed_size + 1) * sizeof(char));

	free(destuffed);

	// Quando da certo enviar um RR


    return destuffed_size + 1;
}

int llwrite(int fd, char* buffer, int length) {
    char *unstuffed = (char *)malloc(sizeof(char)* 32768);
    char *stuffed = (char *)malloc(sizeof(char)* 32768);
    char *trama = (char *)malloc(sizeof(char)* 32768);
    int stuffed_index = 0;

    // Fill Unstuffed

    for (int i = 0; i < length; i++) unstuffed[i] = buffer[i];
    
    // BCC2

    char bcc2 = buffer[0];
    for (int i = 1; i < length + 1; i++) {
        bcc2 = bcc2 ^ buffer[i];
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

    free(unstuffed);


    // Setup Trama
    char temp_C = 0x00;
    trama[0] = FLAG;
    trama[1] = ADDR;
    trama[2] = temp_C;
    trama[3] = ADDR ^ temp_C;
    memcpy(trama + 4 * sizeof(char), stuffed, (stuffed_index + 1) * sizeof(char));
    trama[5 + stuffed_index] = FLAG;

    free(stuffed);

    int temp = write(fd, trama, stuffed_index + 6);

    printf("Bytes written: %d\n", temp);

    free(trama);

    return stuffed_index + 6;

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


