#include <concr/method.h>

#define MAX_INPUT_BUFFER	16384 
/* this constant must also be same as the line in 
 * concr_decrypt.h */

extern void *working_key; 

extern char meta_buffer[MAX_INPUT_BUFFER];

extern void (*decrypt_error)(char *in);
extern int  (*concr_decrypt_input)(char *in, int len);
extern int  (*concr_decrypt_eof)(void);

int concr_rd(char *buf, int len);
int concr_eof(void);
int concr_decrypt(char *in, unsigned int len);
void decode_init(void);

char *concr_guessname(char *argv_0);
void *concr_getkey(gen_key_meth *method, char *hint);

/*#include <concr/elf.h>
#include <concr/method.h>
#include <concr/concr_getkey.h>
#include <concr/concr_decrypt.h>
#include <concr/base64.h> */
