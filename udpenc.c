/*
 * udpenc.c: Encrypt UDP packets
 *
 * Copyright (c) 2008 Vitaly "_Vi" Shukela. Some rights reserved.
 * 
 *
 */

/* in MORE_SECURE mode size of all packets will be increased by 8 bytes */
/* without MORE_SECURE mode long equal plaintext packets produce equal cipher packets */

//#define MORE_SECURE

static const char rcsid[] = "$Id:$";

#include <stdio.h>   /* reading key file, stderr fprintfs */
#include <stdlib.h>  /* exit */
#include <string.h>  /* memset */
#include <sys/socket.h>   
#include <sys/types.h>   
#include <netinet/in.h>
#include <arpa/inet.h>

#include "blowfish.h"

#define BSIZE 4096
#define KEYSIZE 64 /* in bytes */

#ifdef MORE_SECURE

    #define TRAILMAGIC "X\xf7\x73\x77X\x2aX\x07\xa4\x5c\x78X"
    #define TRAILLEN 12
    #define THRESLEN 20

#else

    #define TRAILMAGIC "XXXXXXXX"
    #define TRAILLEN 8
    #define THRESLEN 65536

#endif

#define p_key_name            argv[1]
#define p_plaintext_mode      argv[2]
#define p_plaintext_address   argv[3]
#define p_plaintext_port      argv[4]
#define p_cipher_mode         argv[5]
#define p_cipher_address      argv[6]
#define p_cipher_port         argv[7]
#define p_debug_level         argv[8]

void read_key(const char* fname, BLOWFISH_CTX* ctx);
int get_server_udp_socket(const char* address, int port);
int accept_server_udp_socket(int s, char *buf, int *len);
int get_client_udp_socket(const char* address, int port);
void encrypt(BLOWFISH_CTX* ctx, char* buf, int *len);
void decrypt(BLOWFISH_CTX* ctx, char* buf, int *len);

#define max(a,b) (((a)>(b))?(a):(b))

int main(int argc, char* argv[]){

    BLOWFISH_CTX ctx;

    int plaintext_socket; // user connects here
    int cipher_socket; // encrypted channel here

    int plaintext_input;
    int plaintext_output;
    int cipher_input;
    int cipher_output;

    fd_set rfds;

    char buf[BSIZE];
    int len;

    int debuglevel=0;


    if(argc<=7){
	fprintf(stderr,"\
Usage: udpenc key_file {c|l|-}[oonect|isten] plaintext_address plaintext_port {c|l|-}[oonect|isten] cipher_address cipher_port [verbosity]\n\
\tExample: \"udpenc secret.key l 127.0.0.1 22 l 192.168.0.1 22\" on one side \n\
\tand \"udpenc secret.key l 127.0.0.1 22 c 192.168.0.1 22\" on the other.\n\
\t\"-\" means stdin/stdout for everything (e.g. \n\
\t\"socat exec:'udpenc secret.key - - - l 0.0.0.0 2222' exec:'pppd noauth nodetach notty debug'\")\n");
	exit(1);
    }
    if(argc>8){
	debuglevel=atoi(p_debug_level);
    }
    if(
	    (*p_plaintext_mode!='c'&&*p_plaintext_mode!='l'&&*p_plaintext_mode!='-') ||
	    (*p_cipher_mode!='c'&&*p_cipher_mode!='l'&&*p_cipher_mode!='-') ) {
	fprintf(stderr, "Only 'l' or 'c' or '-' should be as 2'nd and 5'th argument\n");
	exit(1);
    }

    read_key(p_key_name, &ctx);
    
    // Preparing sockets, phase 1: Create sockets

    if(*p_plaintext_mode=='c'){
	plaintext_socket=get_client_udp_socket(p_plaintext_address,      atoi(p_plaintext_port));
	if(debuglevel>=1) fprintf(stderr, "Connected plaintext socket\n");
	plaintext_input=plaintext_socket;
	plaintext_output=plaintext_socket;
    }else
    if(*p_plaintext_mode=='l'){
	plaintext_socket=get_server_udp_socket(p_plaintext_address,      atoi(p_plaintext_port));
	plaintext_input=plaintext_socket;
	plaintext_output=plaintext_socket;
    }else{
	if(debuglevel>=1) fprintf(stderr, "Plaintext is stdin/stdout\n");
        plaintext_input=0;
	plaintext_output=1;
    }

    if(*p_cipher_mode=='c'){
	cipher_socket=get_client_udp_socket(p_cipher_address, atoi(p_cipher_port));
	if(debuglevel>=1) fprintf(stderr, "Connected cipher socket\n");
	cipher_input=cipher_socket;
	cipher_output=cipher_socket;
    }else
    if(*p_cipher_mode=='l'){
	cipher_socket=get_server_udp_socket(p_cipher_address, atoi(p_cipher_port));
	cipher_input=cipher_socket;
	cipher_output=cipher_socket;
    }else{
	if(debuglevel>=1) fprintf(stderr, "Cihper is stdin/stdout\n");
	cipher_input=0;
        cipher_output=1;
    }

    {
	char buf_pl[BSIZE];
	int  len_pl;
	char buf_ci[BSIZE];
	int  len_ci;

	// Preparing sockets, phase 2: Wait for clients for listening sockets, send empty message for connecting ones

	if(*p_plaintext_mode=='c'){
	    write(plaintext_socket,"",1);	
	}else
	if(*p_plaintext_mode=='l'){
	    if(debuglevel>=1) fprintf(stderr, "Accepting plaintext socket\n");
	    accept_server_udp_socket(plaintext_socket, buf_pl, &len_pl);
	    if(debuglevel>=1) fprintf(stderr, "Accepted plaintext socket\n");
	}

	if(*p_cipher_mode=='c'){
	    write(cipher_socket,"",1);	
	}else
	if(*p_cipher_mode=='l'){
	    if(debuglevel>=1) fprintf(stderr, "Accepting cipher socket\n");
	    accept_server_udp_socket(cipher_socket, buf_ci, &len_ci);
	    if(debuglevel>=1) fprintf(stderr, "Accepted cipher socket\n");
	}

	// Preparing sockets, phase 3: Process first messages

	if(*p_cipher_mode=='l'){
	    decrypt(&ctx, buf_ci, &len_ci);
	    write(plaintext_output, buf_ci, &len_ci);
	    if(debuglevel>=1) fprintf(stderr, "Sent first packet to plaintext socket\n");
	}

	if(*p_plaintext_mode=='l'){
	    encrypt(&ctx, buf_pl, &len_pl);
	    write(cipher_output, buf_pl, len_pl);
	    if(debuglevel>=1) fprintf(stderr, "Sent first packet to ciphertext socket\n");
	}
    }

    if(debuglevel>=1){
	fprintf(stderr, "Main loop: plaintext_input=%d plaintext_output=%d cipher_input=%d cipher_output=%d\n",
		plaintext_input, plaintext_output, cipher_input, cipher_output);
    }
    for(;;){
        FD_ZERO(&rfds);
	FD_SET(plaintext_input, &rfds);
	FD_SET(cipher_input, &rfds);

	if(select(max(plaintext_socket, cipher_socket)+1, &rfds, NULL, NULL, NULL)<0){
	    perror("select");
	    exit(2);
	}

	if(FD_ISSET(plaintext_input, &rfds)){
	    if(debuglevel>=3) fprintf(stderr, "]");
	    len=read(plaintext_input, buf, BSIZE);
	    if(len<=0){
		write(plaintext_output, "", 0);
		if(debuglevel>=1) fprintf(stderr,"\nCipher disconnected, terminating link\n");
		exit(0);
	    }
	    encrypt(&ctx, buf, &len);
	    write(cipher_output, buf, len);
	    if(debuglevel>=2) fprintf(stderr, ">");
	}
	
	if(FD_ISSET(cipher_input, &rfds)){
	    if(debuglevel>=3) fprintf(stderr, "[");
	    len=read(cipher_input, buf, BSIZE);
	    if(len<=0){
		write(plaintext_output, "", 0);
		if(debuglevel>=1) fprintf(stderr,"\nCipher disconnected, terminating link\n");
		exit(0);
	    }
	    decrypt(&ctx, buf, &len);
	    write(plaintext_output, buf, len);
	    if(debuglevel>=2) fprintf(stderr, "<");
	}
    }
    fprintf(stderr, "Abnormal termanation\n");
    exit(2);

}

void setup_socket(int* s, struct sockaddr_in* addr, const char* address, int port){
    *s = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof(one));
    
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family      = AF_INET;
    addr->sin_addr.s_addr = inet_addr(address);
    addr->sin_port        = htons(port);
}

int get_server_udp_socket(const char* address, int port){
    int s; 
    struct sockaddr_in addr;

    setup_socket(&s, &addr, address, port);
    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) != 0){
	perror("bind");
	exit(2);
    }

    return s;
}

int accept_server_udp_socket(int s, char *buf, int *len){
    struct sockaddr_in addr;
    int size=sizeof(addr);
    *len=recvfrom(s, buf, BSIZE, 0, (struct sockaddr *) &addr, &size);
    connect(s, (struct sockaddr *) &addr, sizeof(addr));
}

int get_client_udp_socket(const char* address, int port){
    int s; 
    struct sockaddr_in addr;
    setup_socket(&s, &addr, address, port);
    if(connect(s, (struct sockaddr *) &addr, sizeof(addr)) != 0){
	perror("connect");
	exit(2);
    }
    return s;
}

void read_key(const char* fname, BLOWFISH_CTX* ctx){
    FILE* f;
    unsigned char buf[KEYSIZE];

    if(fname[0]=='-' && fname[1]==0){
	f=stdin;
    }else{
	f=fopen(fname, "r");
	if(!f){
	    perror("fopen");
	    exit(1);
	}
    }

    if(fread(&buf, KEYSIZE, 1, f)!=1){
	fprintf(stderr, "Error reading key, it must be at least %d bytes\n", KEYSIZE);
	exit(1);
    }

    fclose(f);

    srand(*(unsigned int*)buf);
    Blowfish_Init (ctx, buf, KEYSIZE);
}

void encrypt(BLOWFISH_CTX* ctx, char* buf, int *len){
    int i;
    if(*len<THRESLEN){
	for(i=0; i<TRAILLEN; ++i){
	    if(TRAILMAGIC[i]=='X'){
		buf[*len+i]=(unsigned char)rand();
	    }else{
		buf[*len+i]=TRAILMAGIC[i];
	    }
	}
	*len+=TRAILLEN;
    }
    for(i=0; i < *len-8; i+=4){
	//fprintf(stderr,"encrypt %d %08X%08X -> ",i, *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
	Blowfish_Encrypt(ctx, (unsigned long*)(buf+i), (unsigned long*)(buf+i+4));
	//fprintf(stderr,"%08X%08X\n",  *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
    }
    for(i=(*len-8)&~7; i >=0; i-=4){
	//fprintf(stderr,"encrypt %d %08X%08X -> ",i, *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
	Blowfish_Encrypt(ctx, (unsigned long*)(buf+i), (unsigned long*)(buf+i+4));
	//fprintf(stderr,"%08X%08X\n",  *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
    }
}
void decrypt(BLOWFISH_CTX* ctx, char* buf, int *len){
    int i;
    if(*len < TRAILLEN){
	// fail, this packet as malformed    
	*len=-1;
	return;
    }
    for(i=0; i < *len-8; i+=4){
	//fprintf(stderr,"decrypt %d %08X%08X -> ",i, *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
	Blowfish_Decrypt(ctx, (unsigned long*)(buf+i), (unsigned long*)(buf+i+4));
	//fprintf(stderr,"%08X%08X\n",  *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
    }
    for(i=(*len-8)&~7; i >=0; i-=4){
	//fprintf(stderr,"decrypt %d %08X%08X -> ",i, *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
	Blowfish_Decrypt(ctx, (unsigned long*)(buf+i), (unsigned long*)(buf+i+4));
	//fprintf(stderr,"%08X%08X\n",  *(unsigned long*)(buf+i), *(unsigned long*)(buf+i+4));
    }
    if(*len >= TRAILLEN && *len<THRESLEN+TRAILLEN){
	*len-=TRAILLEN;     
	for(i=0; i<TRAILLEN; ++i){
	    if((buf[*len+i]!=TRAILMAGIC[i]) && TRAILMAGIC[i]!='X'){
		*len+=TRAILLEN;
		break;
	    }
	}
    }
}
