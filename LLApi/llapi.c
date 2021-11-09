
#include "llapi.h"

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
	char trama[2048];
	int trama_index = 0;
	
	while(true) {
		int res = read(fd, trama + trama_index, 1);
		
		if( trama[trama_index] != FLAG && trama_index == 0) continue;
		if( trama[trama_index] == FLAG ) 
			if( trama_index != 0) break;
			
		trama_index++;
	}
	
	// Check BCC1
	
	if ((trama[ICTRL] ^ trama[IADDR]) != trama[IBBC1]) {
		// Nao envia nada e voltar a ler
	}
	
	// Check BCC2
	
	
	
	
	
	
}

int llwrite(int fd, char* buffer, int length) {
	
}


// EStabelecer ligaçao
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


