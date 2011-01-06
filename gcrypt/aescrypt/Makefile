CC=gcc
LIBS="-lgcrypt"
PROGNAME="aescrypt"

CFLAGS := -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align \
              -Wwrite-strings -Wmissing-prototypes -Wmissing-declarations \
              -Wredundant-decls -Wnested-externs -Winline -Wno-long-long \
              -Wconversion -Wstrict-prototypes


all: cryptinit.o cryptfile.o main.o
	$(CC) $(LIBS) -o $(PROGNAME) secure_init.o cryptfile.o main.o

cryptinit.o: cryptinit.c
	$(CC) -c -o cryptinit.o cryptinit.c

cryptfile.o: cryptfile.c
	$(CC) -c -o cryptfile.o cryptfile.c

main.o: main.c
	$(CC) -c -o main.o main.c

clean:	
	rm -rf *.o a.out $(PROGNAME)

.PHONY:	all clean
