# Makefile for Sender-Receiver TCP project

#Macros
CC = gcc
CFLAGS = -Wall -g

.PHONY: clean all
 

# Makes

all: receiver sender 

sender: Sender.c
	$(CC) $(CFLAGS) Sender.c -o sender

receiver: Receiver.c
	$(CC) $(CFLAGS) Receiver.c -o receiver

clean:
	rm -f *.o *.a receiver sender
