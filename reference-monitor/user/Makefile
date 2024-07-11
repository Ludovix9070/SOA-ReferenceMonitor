CC=gcc 
CFLAGS=-Wall

all: syscall utilslib user	

user: user.c lib/syscall.o lib/utilslib.o
	gcc -o user user.c lib/syscall.o lib/utilslib.o

syscall: lib/syscall.c
	gcc -o lib/syscall.o -c lib/syscall.c

utilslib: lib/utilslib.c
	gcc -o lib/utilslib.o -c lib/utilslib.c

clean: 
	rm -f user user.o lib/syscall.o lib/utilslib.o
	
run: 
	./user
