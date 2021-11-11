#ifndef LLAPI_H
#define LLAPI_H


#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alarm.h"

#define RECEIVER 0x00
#define TRANSMITER 0x01
#define FLAG 0x7E
#define SET 0x03
#define UA 0x07
#define ADDR 0x03
#define IADDR 1
#define ICTRL 2
#define IBBC1 3


extern int alarm_flag;
extern int alarm_count;


/**
 * @brief establish the connection between 2 systems 
 * 
 */
int llopen(int fd, int state);

int llread(int fd, char* buffer);

int llwrite(int fd, char* buffer, int length);


/**
 * @brief Read and verification of the message
 * 
 */
int read_message(int fd, char * message);


#endif
