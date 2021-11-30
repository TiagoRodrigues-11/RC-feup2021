

all: ret

ret: main.o alarm.o llapi.o
	gcc -g -Wall -Wextra -o llapi main.o alarm.o llapi.o

main.o: main.c alarm.h llapi.h
	gcc -c main.c

alarm.o: alarm.c alarm.h
	gcc -c alarm.c

llapi.o: llapi.c llapi.h
	gcc -c llapi.c

clean:
	rm llapi *.o
