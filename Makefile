all: udpenc

udpenc: udpenc.c blowfish.c blowfish.h
	${CC} ${CFLAGS} ${LDFLAGS} -o udpenc udpenc.c blowfish.c -O2

# this is for checkinstall
install: udpenc
	install -o root -g staff udpenc /usr/bin/
