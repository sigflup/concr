#define PROC_PATH	"/proc/self/exe"

#define KEY_MOD		2049	
#define KEYSPACE	5000
#define SYMBOL_NAME	"concr_key"

#define RSA_SIZE_LESS	11

#define MAX_NAME_TABLE_LEN 	0xfffff

extern void *working_key;

extern int quiet;

typedef struct {
 int pub_len, priv_len;
 char data[KEYSPACE];
} key_lump;

typedef struct {
 ELF_Off offset;
 ELF_Word size;
 ELF_Addr address;
 unsigned int index;
} seg_t;

typedef struct {
 char *names;
 unsigned int len;
} name_table_t;

/* mainly here for the symbol check */

char *concr_guessname(char *argv_0);

int concr_baby(char *baby_name, char *elf_name, char *key_name, char *hint,
         void *user,key_lump *newkey,gen_key_meth *method);

off_t get_symbol(char *name, ELF_Addr *addr, 
  seg_t *segment, name_table_t *symbol_names, 
  gen_key_meth *method, seg_t *symtab, seg_t *strtab,  
  void *elf_io_user, void *user, char *elf_name,
  ELF_Ehdr *elf_head, unsigned int size);

void *concr_getkey(gen_key_meth *method, char *hint);

