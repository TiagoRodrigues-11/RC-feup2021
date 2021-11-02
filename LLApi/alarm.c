#include "alarm.h"

void atend() {
    printf("Alarm #%d\n", ++alarm_count);
    alarm_flag = 1;
}