#define MAX_LINE_LEN	2048

typedef struct {
 char *(*rehint)(void *user, char *hint);
 void *(*start)(char *hint,char **baby_name, char **elf_name, char **key_name);
 void (*setup_progress)(void);
 void (*gen_progress)(int a, int b, void *user);
 void (*end_progress)(void *user);
 void (*public_key_out)(unsigned char *data, int len, void *user);
 void (*finish)(void *user);
 void *(*open_elf)(char *hint, void *user, unsigned int *size); 
 void *(*open_baby)(char *hint, void *user);
 int (*read)(void *store, int len, void *io_user, void *user);
 int (*write)(void *store, int len, void *io_user, void *user);
 int (*seek)(unsigned int pos, void *io_user, void *user);
 int (*close)(void *io_user, void *user);
 int (*chmod)(void *io_user, void *user, mode_t mod);
 void (*error)(void *user, char *format, ...);
 char *(*prompt_new_binary)(void *user);
} gen_key_meth;

extern gen_key_meth concr_method;
