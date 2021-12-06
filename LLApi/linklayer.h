#ifndef LLAPI_H
#define LLAPI_H


#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "alarm.h"

#define BAUDRATE B38400
#define RECEIVER 0x00
#define TRANSMITER 0x01
#define FLAG 0x7E
#define DISC 0x0B
#define SET 0x03
#define UA 0x07
#define ADDR 0x03
#define IADDR 1
#define ICTRL 2
#define IBCC1 3
#define RR(n) ((n << 7) | 0x05)
#define REJ(n) ((n << 7) | 0x01)

extern int alarm_flag;
extern int alarm_count;
extern int state;

/**
 * Establish the connection between 2 systems
 * 
 * @param port Number of port
 * @param state State: Transmiter/Receiver
 * @return int -1 in case of error, 0 otherwise
 */
int llopen(int port, int state);


/**
 * Close connection
 * 
 * @param fd File Descriptor
 * @return int -1 in case of error , 0 otherwise
 */
int llclose(int fd);

/**
 * Read from serial port to buffer according to protocol
 * 
 * @param fd File Descriptor
 * @param buffer Buffer to write to
 * @return int 
 */
int llread(int fd, char* buffer);


/**
 * Write length number of bytes from buffer to serial port indicated by fd
 * 
 * @param fd File Descriptor
 * @param buffer Buffer to read from
 * @param length NUmber of bytes from buffer to read
 * @return int -1 in case of error, 0 otherwise
 */
int llwrite(int fd, char* buffer, int length);

/**
 * Read supervision trama
 * 
 * @param fd File Descriptor
 * @param message message to write to 
 * @return int -1 in case of error, 0 otherwise
 */
int read_message(int fd, unsigned char * message);


#endif
