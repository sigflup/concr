#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#include <sys/stat.h>
#include <sys/errno.h>

#include <sys/types.h>
#include <dirent.h>

#include "elf.h"
#include "method.h"
#include "concr_getkey.h"


#include "concr_decrypt.h"

#include "base64.h"

#define MAX_BUF	4096
#define KEYRING	"/var/db/confcrypt/"

char *keyring_path = 0;

FILE *key = (FILE *)0, *in, *out;
char *in_name, *out_name, *key_name;

void confcrypt_usage(void) {
 printf("usage:\n"
        "\tconfcrypt -key <public key> [-in <input>] [-out <output>]\n\n"
	"\tif -in and/or -out is omitted crypt will use\n"
	"\tstandard in and/or standard out instead\n");
 exit(0);
}

void out64(char in) {
 fputc(in, out);
}

FILE *open_from_path(char *path, char *name) {
 char buffer[MAX_BUF];
 FILE *ret = 0;
 DIR *dirp;
 int len;
 int found = 0;
 struct dirent *dp;

 len = strlen(name);
 if((dirp = opendir(path))) {
  while((dp = readdir(dirp))!=NULL)
#ifdef NONAMLEN 
   if(!strncmp(dp->d_name, name, 256)) { /* 256 taken from linux man-page */
#else
   if(dp->d_namlen == len && 
       !strncmp(dp->d_name, name, len)) {
#endif
    found = 1;
    break; 
   } 
  (void)closedir(dirp);
 } else {
  fprintf(stderr, "%s (keyring): %s\n", path, strerror(errno));
  exit(0);
 }

 if(found == 0) {
  fprintf(stderr, "%s not found in working directory or keyring\n"
                  "keyring is %s\n", name, path);
  exit(0);
 }

 snprintf(buffer, MAX_BUF-1, "%s/%s", path, name);
 
 if((ret = fopen(buffer, "rb"))<=0) {
  perror(buffer);
  exit(0);
 }
 return ret;
}

int main(int argc, char **argv) {
 int i, len;
 int buf_len;
 unsigned char *buf;
 int out_len;
 unsigned char *out_buf;

 RSA *rsa = 0;
 in = stdin;
 in_name = "stdin";
 out = stdout;
 out_name ="stdout";
 key_name = (char *)0;
 keyring_path = (char *)KEYRING;

 for(i=1;i<argc;i++) {
#define CHECK(STRING,FP,MODE,NAME) \
  if(strncmp(STRING, argv[i], strlen(STRING))==0) { \
   if((i+1)>argc) confcrypt_usage(); \
   if((FP = fopen(argv[i+1], MODE))<=0) { \
    perror(argv[i+1]); \
    exit(0); \
   } \
   NAME=argv[i+1]; \
   i++; \
  }
#define CHECK_NAME(STRING,NAME) \
 if(strncmp(STRING,argv[i],strlen(STRING))==0) { \
  if((i+1)>argc) confcrypt_usage(); \
  NAME = argv[i+1]; \
  i++; \
 }

 CHECK("-in",in,"rb",in_name);
 CHECK("-out",out,"w+",out_name);

 CHECK_NAME("-key",key_name);
 CHECK_NAME("-ring",keyring_path);

#undef CHECK_NAME
#undef CHECK
 } 

 if(key_name == (char *)0) confcrypt_usage();

 if((key = fopen(key_name, "rb"))<=0) {
  /* try keyring_path */
  if((buf = getenv("CONFCRYPT_KEYRING"))>0)
   keyring_path = buf;
  if((key = open_from_path(keyring_path, key_name))<=0) /* should not return
							   if there's an 
							   error */
							 
   confcrypt_usage(); 
 } 

 if((rsa = PEM_read_RSA_PUBKEY(key,NULL,NULL,NULL))==0) {
  printf("can't use %s\n", key_name);
  exit(0);
 }

 buf_len = RSA_size(rsa);
 if((buf = (unsigned char *)malloc(buf_len))<=0) {
  perror("buf malloc");
  exit(0);
 }
 if((out_buf = (unsigned char *)malloc(buf_len))<=0) {
  perror("out_buf malloc");
  exit(0);
 }

 base64_reset();
 base64_wrap = 64;
 base64_out64_callback = out64;

 fwrite(start_block, 1, strlen(start_block), out);
 for(;;) {
  len = fread(buf, 1, buf_len-RSA_SIZE_LESS, in);
  if(len == 0) {
   if(feof(in)) break;
   perror(in_name);
  }
  out_len = RSA_public_encrypt(len, buf, out_buf,rsa,RSA_PKCS1_PADDING);
  
  for(i=0;i<out_len;i++) 
   base64_outbyte(out_buf[i]);
 }
 base64_outbyte(-1);
 fputc('\n', out);
 fwrite(end_block, 1, strlen(end_block), out);
 
 free(buf);
 free(out_buf);

 if(out == stdout)
  fflush(stdout);
 else
  fclose(out);

 if(in != stdin)
  fclose(in);

 return 0;
}
