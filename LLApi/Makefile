

all: ret

ret: main.o alarm.o linklayer.o
	gcc -g -Wall -Wextra -o llapi main.o alarm.o linklayer.o

main.o: main.c alarm.h linklayer.h
	gcc -c main.c

alarm.o: alarm.c alarm.h
	gcc -c alarm.c

linklayer.o: linklayer.c linklayer.h
	gcc -c linklayer.c

clean:
	rm llapi *.o
