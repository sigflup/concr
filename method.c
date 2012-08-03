#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <signal.h>
#include "method.h"

#define BABY_NAME	"baby"
#define PUBLIC_KEY_NAME	"public.key"

struct termios save;

void restore(int sigraised) {
 if(tcsetattr(fileno(stdin), TCSANOW, &save)==-1){
   perror("method: tcsetattr");
   exit(0);
  }
}

typedef struct {
 char *publickey_name;
 char *baby_name;

 /* only in here so we can do a free at finish */
 char *g_baby_name;
 char *g_key_name;
 char *g_elf_name;
} state_t;

const char progress_chars[4] = { "|/-\\" };
int progress_pos;

char *concr_rehint(void *user, char *hint) {
 state_t *obj;
 obj = (state_t *)user;
 char *new;
 if(hint != (char *)0) 
  new = strdup(hint);
 else
  new = (char *)0;

 obj->g_elf_name = new;
 return new;
}

void *concr_start(char *hint, char **baby_name, char **elf_name,
                  char **key_name) {
 state_t *new;
 if( (new = (state_t *)malloc(sizeof(state_t)))<=0) {
  perror("concr_setup_progress malloc");
  exit(-1);
 }
 new->publickey_name = PUBLIC_KEY_NAME;
 new->baby_name = BABY_NAME;

 *baby_name = strdup(new->baby_name);
 *key_name =  strdup(new->publickey_name);
 if(hint != (char *)0)
  *elf_name =  strdup(hint);
 else 
  *elf_name = (char *)0;

 new->g_baby_name = *baby_name;
 new->g_key_name = *key_name;
 new->g_elf_name = *elf_name;

 return (void *)new;

}

void concr_setup_progress(void) { 
 printf("generating rsa keypair.. (");
 fflush(stdout);
 progress_pos = -1;
}

void concr_gen_progress(int a, int b, void *user) {
 switch(a) {
  case 0:
  case 1:
   if(progress_pos == -1)
    progress_pos =0;
   else
    printf("\10\10");
   putchar(progress_chars[progress_pos%4]);
   putchar(')');
   progress_pos++;
   break;
 }
 fflush(stdout);
}

void concr_end_progress(void *user) {
 if(progress_pos!=-1)
  printf("\10\10\10");
 printf("done\n");
}

void concr_public_key_out(unsigned char *data, int len, void *user) {
 state_t *obj;
 FILE *fp;

 obj = (state_t *)user;
 if((fp = fopen(obj->publickey_name, "w+"))<=0) {
  perror(obj->publickey_name);
  exit(0);
 }

 fwrite(data, len, 1, fp);
 fclose(fp);
}

void concr_finish(void *user) {
 state_t *obj;
 obj = (state_t *)user;

 printf("wrote executable %s, saved public key to %s\n",
   obj->baby_name, obj->publickey_name);

 puts("\n"
        "***********************************************\n"
        "* Be sure to:                                 *\n"
        "* $ sudo chown root <new executable>          *\n"
        "* $ sudo chmod 111 <new executable>           *\n"
        "* in order to prevent the contents of the new *\n"
        "* executable being read and the private key   *\n"
        "* stolen                                      *\n"
        "***********************************************\n");

 free(obj->g_baby_name);
 free(obj->g_key_name);
 free(obj->g_elf_name);
 free(obj);
}

void *concr_open_elf(char *hint, void *user, unsigned int *size) {
 FILE *fp;
 struct stat qstat;

 if((fp = fopen(hint, "rb"))<=0) {
  perror(hint);
  return NULL;
 }

 fstat(fileno(fp), &qstat);

 *size = qstat.st_size;

 return (void *)fp;
}

void *concr_open_baby(char *hint, void *user) {
 state_t *obj;
 FILE *fp;

 obj = (state_t *)user;

 if((fp = fopen(obj->baby_name, "w+"))<=0) {
  perror(obj->baby_name);
  exit(0);
 }
 
 return (void *)fp;
}

int concr_read(
  void *store, int len, void *io_user, void *user) {
 FILE *fp;
 fp = (FILE *)io_user;
 return fread(store,len,1,fp);
}

int concr_write(
  void *store, int len, void *io_user, void *user) {
 FILE *fp;
 fp = (FILE *)io_user;
 return fwrite(store,len,1,fp);
}

int concr_seek(unsigned int pos, void *io_user, void *user) {
 FILE *fp;
 fp = (FILE *)io_user;
 return fseek(fp, pos, SEEK_SET);
}

int concr_close(void *io_user, void *user) {
 FILE *fp;
 fp = (FILE *)io_user;
 return fclose(fp); 
}

int concr_chmod(void *io_user, void *user, mode_t mode) {
 FILE *fp;
 fp = (FILE *)io_user;
 return fchmod(fileno(fp), mode); 
}


void concr_error(void *user, char *format, ...) {
 va_list ap;
 va_start(ap, format);
 vfprintf(stderr, format, ap);
 va_end(ap); 
}

char *concr_prompt_new_binary(void *user) {
 struct termios ios;
 char *new;
 int i=0;
 char dat;

 if(tcgetattr(fileno(stdin), &ios)==-1){
  perror("concr_prompt_new_binary: tcgetattr");
  exit(0);
 }
 memcpy(&save, &ios, sizeof(struct termios));

 signal(SIGHUP, restore);
 signal(SIGINT, restore);

 cfmakeraw(&ios);
 if(tcsetattr(fileno(stdin), TCSANOW, &ios)==-1){
  perror("concr_prompt_new_binary: tcsetattr");
  exit(0);
 }
 for(;;) {
  new = (char *)malloc(MAX_LINE_LEN);
  new[MAX_LINE_LEN-1] = 0;
  printf("enter path, 'q' to quit> ");
  for(;i<MAX_LINE_LEN;) {
   if(fread(&dat, 1,1, stdin)==0) break; 
   if((dat == '\r') ||
      (dat == '\n')) break;
   if(dat!=0x7f) {
    new[i] = dat;
    putchar(dat);
    fflush(stdout);
    i++;
   } else {
    if(i!=0) {
     putchar('\10');
     putchar(' ');
     putchar('\10');
     fflush(stdout);
     new[i] = 0;
     i--;
    }
   }
  }
  new[i] = 0;
  putchar('\n');
  putchar('\r');
  if(new[0]!=0) break;
 }
 restore(0);
 signal(SIGHUP, SIG_DFL);
 signal(SIGINT, SIG_DFL);

 putchar('\n');
 if((new[0] == 'q' ||
     new[0] == 'Q')&&
    (new[1] == 0))
  return (char *)0;

 return new;
}

gen_key_meth concr_method  = {
 concr_rehint,
 concr_start,
 concr_setup_progress,
 concr_gen_progress,
 concr_end_progress,
 concr_public_key_out,
 concr_finish,
 concr_open_elf,
 concr_open_baby,
 concr_read,
 concr_write,
 concr_seek,
 concr_close,
 concr_chmod,
 concr_error,
 concr_prompt_new_binary,
};
