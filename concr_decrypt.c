#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <sys/errno.h>

#include "elf.h"
#include "method.h"
#include "concr_getkey.h"
#include "concr_decrypt.h"

#include "base64.h"
#include "fifo.h"

#ifdef META

#define GET_METASTREAM \
 read_char_fifo(&meta_fifo)

#define METASIZE \
 (meta_fifo.tail - meta_fifo.head)

#define PUT_METASTREAM(X) \
 write_char_fifo(&meta_fifo, X);

#endif


#define GET_INSTREAM \
 read_char_fifo(&input_fifo)

#define INSIZE \
 (input_fifo.tail - input_fifo.head)

#define PUT_DECSTREAM(X) \
 write_char_fifo( &decrypt_fifo, X);

#define GET_DECSTREAM \
 read_char_fifo(&decrypt_fifo)

#define DECSIZE \
 (decrypt_fifo.tail - decrypt_fifo.head)

#define PUT_CIPSTREAM(X) \
 write_char_fifo( &ciphertxt_fifo, X);

#define GET_CIPSTREAM \
 read_char_fifo(&ciphertxt_fifo)

#define CIPSIZE \
 (ciphertxt_fifo.tail - ciphertxt_fifo.head)


int input_eof = 0;
int drain_dec = 0;
int input_mode = PLAIN;
int search_i = 0;
char search_buf[1024]; /* large enough to contain start or end blocks */

void (*decrypt_error)(char *in) = 0;
int (*concr_decrypt_input)(char *in, int len) = 0;
int (*concr_decrypt_eof)(void) = 0;

char_fifo_t decrypt_fifo = { (char *)0, 0,0 };
char_fifo_t ciphertxt_fifo = { (char *)0, 0,0 };
char_fifo_t input_fifo = { (char *)0,0,0};

char *decrypt_buf = (char *)0;

#ifdef META
char meta_buffer[MAX_INPUT_BUFFER];

char_fifo_t meta_fifo = { (char *)0,0,0};
#endif

void flush_ciphertxt_stream(void) {
 int decrypt_len;
#define L RSA_size((RSA *)working_key)

 while(CIPSIZE >= L) {
  decrypt_len = RSA_private_decrypt(
   L, &ciphertxt_fifo.buf[ciphertxt_fifo.head],
   decrypt_buf, (RSA *)working_key, RSA_PKCS1_PADDING);
  if(decrypt_len == -1) {
   ERR_load_crypto_strings();
   if((int)decrypt_error == 0)
    fprintf(stderr,"\r\33[K"
            "RSA decrypt: %s\n", ERR_reason_error_string(ERR_get_error()));
   else
    decrypt_error((char *)ERR_reason_error_string(ERR_get_error()));
   ERR_free_strings(); 
   return;

  } 

  shrink_char_fifo(&ciphertxt_fifo, L);
  write_buf_fifo(&decrypt_fifo, decrypt_buf, decrypt_len);
#ifdef META
  for(i = 0;i<decrypt_len;i++)
   PUT_METASTREAM(CIPHER); 
#endif
 }

#undef L
}

void base64_byte(unsigned char in) { 
 PUT_CIPSTREAM(in);
 flush_ciphertxt_stream();
}

void switch_mode(int in) {
 input_mode = in;
 if(in == PLAIN) {
  base64_in64(-1);
  flush_ciphertxt_stream();
  base64_reset();
 }

}

#ifdef META
void put_decstream(char in) {
 PUT_DECSTREAM(in);
 PUT_METASTREAM(PLAIN);
}
#endif

int concr_eof(void) {
 return input_eof;
}

int concr_rd(char *buf, int len) {
 char buffer[MAX_INPUT_BUFFER];
 int count = 0;
 char dat;
 int i;
#define S search_buf
#define I search_i
#define D dat 

 int l;
 int j;

 if(drain_dec == 0) {
  if((l = concr_decrypt_input(buffer, len))<=0) {
   if(concr_decrypt_eof()) {
    switch_mode(PLAIN);
    drain_dec = 1;
   }
   l = 0;
  }
 } else {
  if(DECSIZE == 0) {
   input_eof = 1;
   return -1;
  }
  l =0;
 }

 if(l!= 0) {
  write_buf_fifo(&input_fifo, buffer, l);

  for(i=0;i<l;i++) {
   dat = GET_INSTREAM;
 
   if(input_mode == PLAIN) {
#define SEARCH_FOR(X, Y, Z) \
    {\
    if(D == X[I]) { \
     S[I] = D; \
     if(X[++I] == 0) { \
      switch_mode(Y); \
      I = 0; \
     } \
    } else \
     if(I==0) { \
      Z(D); \
     } else { \
      for(j=0;j<I;j++) \
       Z(S[j]); \
      I = 0; \
      Z(D); \
     } \
    }

#ifdef META
    SEARCH_FOR(start_block, CIPHER, put_decstream); 
#else
    SEARCH_FOR(start_block, CIPHER, PUT_DECSTREAM); 
#endif
   } else {
    SEARCH_FOR(end_block, PLAIN, base64_in64);
   }

  }
 }

 count = DECSIZE;

 if(count!=0) {
  if(count > len)
   count = len;

  read_buf_fifo(&decrypt_fifo, buf, count);
#ifdef META
  read_buf_fifo(&meta_fifo, meta_buffer, count);
#endif
 }
 return count;
#undef S
#undef I
#undef D

}


void decode_init(void) {

 free_fifo(&input_fifo);
 free_fifo(&ciphertxt_fifo);
 free_fifo(&decrypt_fifo);
#ifdef META
 free_fifo(&decrypt_fifo);
#endif

 base64_inbyte_callback = base64_byte;
 base64_reset();

 if(decrypt_buf != (char *)0)
  free(decrypt_buf);
 
 decrypt_buf = (char *)malloc(RSA_size((RSA *)working_key));

 input_eof = 0;
}
