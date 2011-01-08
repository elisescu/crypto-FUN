CC=gcc
LIBS="-lgcrypt"
PROGNAME="aescrypt"

CFLAGS := -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align \
              -Wwrite-strings -Wmissing-prototypes -Wmissing-declarations \
              -Wredundant-decls -Wnested-externs -Winline -Wno-long-long \
              -Wconversion -Wstrict-prototypes -g

all: cryptinit.o cryptfile.o main.o
	$(CC) $(CFLAGS) $(LIBS) -o $(PROGNAME) secure_init.o cryptfile.o main.o

cryptoinit.o: cryptoinit.c
	$(CC) $(CFLAGS) -c -o cryptoinit.o cryptoinit.c

cryptfile.o: cryptfile.c
	$(CC) -c -o cryptfile.o cryptfile.c

init_test: init_test.o cryptoinit.o
	$(CC) $(CFLAGS) $(LIBS) -o init_test init_test.o cryptoinit.o

init_test.o: init_test.c
	$(CC) -c -o init_test.o init_test.c

main.o: main.c
	$(CC) -c -o main.o main.c

clean:	
	rm -rf *.o a.out $(PROGNAME) init_test

.PHONY:	all clean
