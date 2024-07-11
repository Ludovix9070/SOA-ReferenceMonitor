CC=gcc 
CFLAGS=-Wall

all: utilslib testing	

testing: testing.c ../lib/utilslib.o
	gcc -o testing testing.c ../lib/utilslib.o

utilslib: ../lib/utilslib.c
	gcc -o ../lib/utilslib.o -c ../lib/utilslib.c

clean: 
	rm -f testing testing.o ../lib/utilslib.o
	
run: 
	./testing
