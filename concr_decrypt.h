#define MAX_INPUT_BUFFER	16384	

#define FIFO_CHUNK	4096
#define BASE64_LINE	65	

enum {
 PLAIN, 
 CIPHER
};

extern void (*decrypt_error)(char *in);
extern int (*concr_decrypt_input)(char *in, int len);
extern int (*concr_decrypt_eof)(void);

int concr_rd(char *buf, int len);
int concr_eof(void);
int concr_decrypt(char *in, unsigned int len);

#ifdef META
extern char meta_buffer[MAX_INPUT_BUFFER];
#endif

extern int input_mode;

void decode_init(void);
