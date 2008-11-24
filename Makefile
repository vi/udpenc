all: udpenc

udpenc: udpenc.c blowfish.c blowfish.h
	${CC} ${CFLAGS} ${LDFLAGS} -o udpenc udpenc.c blowfish.c -O2
