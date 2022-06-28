# Makefile for project
CC=g++
FLAGS=-Wall -Wextra

all: proj

proj:
	$(CC) main.cpp $(FLAGS) -o ipk-sniffer -lpcap

clean:
	rm ipk-sniffer