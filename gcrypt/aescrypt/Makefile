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

cryptofile.o: cryptofile.c
	$(CC) $(CFLAGS) -c -o cryptofile.o cryptofile.c

init_test: init_test.o cryptoinit.o metakey.o cryptofile.o
	$(CC) $(CFLAGS) $(LIBS) -o init_test init_test.o cryptoinit.o metakey.o cryptofile.o

init_test.o: init_test.c
	$(CC) $(CFLAGS) -c -o init_test.o init_test.c

metakey.o: metakey.c
	$(CC) $(CFLAGS) -c -o metakey.o metakey.c

main.o: main.c
	$(CC) $(CFLAGS) -c -o main.o main.c

clean:	
	rm -rf *.o tags a.out $(PROGNAME) init_test 

ctags:
	ctags *.c *.h >tags

.PHONY:	all clean
