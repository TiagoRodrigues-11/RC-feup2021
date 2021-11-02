#ifndef ALARM_H
#define ALARM_H


#include <stdio.h>
#include <unistd.h>


extern int alarm_flag;
extern int alarm_count;

/**
 * @brief Alarm handle
 * 
 */
void atend();

#endif 