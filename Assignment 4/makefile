### Makefile for ICMP project ###

#Macros:
CC = gcc
CFLAGS = -Wall -g
.PHONY: clean all

#Make
all: ping watchdog better_ping

ping: ping.c
	$(CC) $(CFLAGS) ping.c -o parta
	
watchdog: watchdog.c
	$(CC) $(CFLAGS) watchdog.c -o watchdog
	
better_ping: better_ping.c
	$(CC) $(CFLAGS) better_ping.c -o partb

#Clean up
clean:
	rm -f *.o parta watchdog partb
