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

#include "elf.h"
#include "method.h"
#include "concr_getkey.h"


#include "concr_decrypt.h"

#include "base64.h"

void *working_key;

int quiet = 1;

char *concr_guessname_garbage = (char *)0;

/* Keep const and initialized, key should be 
 * initialized read-only-data */

const key_lump concr_key = { 0,0,{0} };


/* symbol names are hard-coded here. We check these to verify 
 * that we have the binary's elf, they should be in the .text
 * section */

typedef struct {
 char *name;
 void *symbol;
} sym_name;

sym_name symbol_check[] = {
 {"concr_guessname", concr_guessname},
 {"concr_baby", concr_baby},
 {"get_symbol", get_symbol},
 {"concr_getkey", concr_getkey},
 {(char *)0, NULL}
};

void concr_nonroot(uid_t ownerid, char *path) {
 puts("this program needs to have root ownership and marked --x--x--x\n");  
 if(getuid() != ownerid) {
//  puts("deleting...\n");
  /*XXX delete here */
 }
}


void *concr_getkey(gen_key_meth *method, char *hint) {
 struct stat qstat;
 void *user;
 char *baby_name, *elf_name, *key_name;
 RSA *rsa = 0;
 BIO *public, *private; 
 key_lump *new;
 unsigned char *pub_block, *priv_block;
 unsigned int len;

 if((void *)method == NULL)
  method = &concr_method;
 

 if(concr_key.pub_len + concr_key.priv_len <= KEYSPACE) {
  public =BIO_new_mem_buf(
    (unsigned char *)concr_key.data, concr_key.pub_len);
  private=BIO_new_mem_buf(
    (unsigned char *)&concr_key.data[concr_key.pub_len],concr_key.priv_len);

  rsa = PEM_read_bio_RSAPublicKey(public, NULL, NULL, NULL);
  rsa = PEM_read_bio_RSAPrivateKey(private, &rsa, NULL, NULL); 

  BIO_free(public);
  BIO_free(private);
  if(rsa != 0) {
   if(RSA_check_key(rsa)) { 
#ifndef NOROOTCHECK
   if(stat(PROC_PATH, &qstat) == 0) {
    if(qstat.st_size != (off_t)0) {
     if(qstat.st_uid != (uid_t)0)
      concr_nonroot(qstat.st_uid, PROC_PATH);
    }
   } else { 
    /* XXX openbsd non /proc root ownership check here */
   }
#endif
    if(concr_guessname_garbage != (char *)0)
     free(concr_guessname_garbage);
    return (void *)rsa;
   } else 
    RSA_free(rsa);
  }
 }
 user = method->start(hint, &baby_name, &elf_name, &key_name);
 method->setup_progress();
 rsa = RSA_generate_key(KEY_MOD,17,method->gen_progress, user);
 method->end_progress(user);

 public = BIO_new(BIO_s_mem());
 private = BIO_new(BIO_s_mem());

 new = (key_lump *)malloc(sizeof(key_lump));

 PEM_write_bio_RSAPublicKey(public, rsa);
 PEM_write_bio_RSAPrivateKey(private, rsa, 
   (const EVP_CIPHER *)NULL,(unsigned char *)NULL,0,
   (pem_password_cb *)NULL,(void *)NULL);
 
 new->pub_len = BIO_get_mem_data(public, &pub_block);
 new->priv_len =BIO_get_mem_data(private, &priv_block);

 memcpy(new->data, pub_block, new->pub_len);
 memcpy(&new->data[new->pub_len], priv_block, new->priv_len);

 BIO_free(public);
 BIO_free(private);

 if(concr_baby(baby_name, elf_name, key_name, hint,user, new, method)!=0) {
  public = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(public, rsa);
  len = BIO_get_mem_data(public, &pub_block);
  method->public_key_out(pub_block, len, user);
  BIO_free(public);

  method->finish(user);
 } else 
  return 0;
 
 if(concr_guessname_garbage != (char *)0)
  free(concr_guessname_garbage);

 free(new);
 exit(0);
// return (RSA *)0;
}

off_t get_symbol(char *name, ELF_Addr *addr, 
  seg_t *segment, name_table_t *symbol_names, 
  gen_key_meth *method, seg_t *symtab, seg_t *strtab,  
  void *elf_io_user, void *user, char *elf_name,
  ELF_Ehdr *elf_head, unsigned int size) {

 unsigned int num_symbols;
 int i, j =0;
 ELF_Sym symbol;
 ELF_Shdr sect;
 seg_t section;
 off_t offset;

 memcpy(&section, segment, sizeof(seg_t));
 num_symbols = symtab->size;

 for(i = 1; i<num_symbols;i++) {
  method->seek(symtab->offset + (i*sizeof(ELF_Sym)), elf_io_user, user);
  method->read(&symbol, sizeof(ELF_Sym), elf_io_user, user);
  if(strncmp(&symbol_names->names[symbol.st_name%strtab->size], name, 
     strtab->size - (symbol.st_name%strtab->size))==0) {
   j = 1;
   switch(symbol.st_shndx) {
    case SHN_ABS:
    case SHN_COMMON:
    case SHN_UNDEF:
     if(!quiet) 
      method->error(user, "can't read %s, symbol %s index type unexpected\n", 
                    elf_name, name);
     return 0;
    case SHN_XINDEX:
     printf("%s(%d): XXX no extended index yet\n", __FILE__, __LINE__);
     exit(0);
    default:
     if(section.index != (symbol.st_shndx)) {
      if(!quiet)
       method->error(user,"%s(%d): warning: expected %s to be in *segment\n", 
	             __FILE__, __LINE__, name);
      if((elf_head->e_shoff+(symbol.st_shndx*elf_head->e_shentsize)+
	  elf_head->e_shentsize) >size) {
       if(!quiet)
        method->error(user,"can't read %s, symbol section index out of bounds\n"
 	              ,elf_name);
       return 0;
      }
      method->seek(elf_head->e_shoff+(symbol.st_shndx*elf_head->e_shentsize),
	           elf_io_user, user);
      method->read(&sect, sizeof(ELF_Shdr), elf_io_user, user);
      section.offset = sect.sh_offset;
      section.address =sect.sh_addr;
     }
     break; 
   }
   break;
  }

 }

 if(j == 0) {
  if(!quiet) 
   method->error(user,
                "can't read %s, %s symbol not found\n", elf_name, name);
  return (off_t)0;
 }

 if(symbol.st_value < section.address) {
  if(!quiet)
   method->error(user, "can't read %s, %s's address is below section bounds\n",
           elf_name, name);
  return (off_t)0;
 }
 *addr = symbol.st_value;
 offset = (off_t)((symbol.st_value - section.address) + section.offset);
 if(offset > (off_t)size) {
  if(!quiet)
   method->error(user, "can't read %s, %s's file-offset out of bounds\n",
          elf_name, name);
  return (off_t)0;
 }


 return offset;
}

int concr_baby(char *baby_name, char *elf_name, char *key_name, char *hint,
         void *user,key_lump *newkey,gen_key_meth *method) {
 void *elf_io_user = NULL, *baby_io_user = NULL;
 unsigned int size;
 struct stat qstat;

 unsigned char *buffer; 
 unsigned int file_offset;
 unsigned int offset;
 unsigned int len;
 int store;

 char *new_name;

 name_table_t sec_table, symbol_names;

 seg_t rodata, symtab, strtab;
 seg_t text;
 ELF_Addr addr;
 int i;
 ELF_Ehdr elf_head;
 ELF_Shdr sect;

 if(elf_name == (char *)0)
  goto fail;

 if((elf_io_user = method->open_elf(elf_name,user, &size))==NULL)
  goto fail;

 if( size < sizeof(ELF_Ehdr)) {
  method->error(user, "can't read %s\n", elf_name);
  goto fail;
 }

 method->read(&elf_head, sizeof(ELF_Ehdr), elf_io_user, user);
 
 if((elf_head.e_ident[0] != ELFMAG0) ||
    (elf_head.e_ident[1] != ELFMAG1) ||
    (elf_head.e_ident[2] != ELFMAG2) ||
    (elf_head.e_ident[3] != ELFMAG3)) {
  if(!quiet) method->error(user, "%s has invalid magic\n", elf_name);
  goto fail;
 }

 if((elf_head.e_shoff + (elf_head.e_shnum * elf_head.e_shentsize))>size) {
  if(!quiet)
   method->error(user, "can't read %s, un-expected file size\n", elf_name);
  goto fail;
 }

 if(elf_head.e_shentsize < sizeof(ELF_Shdr)) {
  if(!quiet)
   method->error(user,"section header size-mismatch, can't read %s\n",elf_name);
  goto fail;
 }


 method->seek(elf_head.e_shoff + (elf_head.e_shentsize * elf_head.e_shstrndx),
              elf_io_user, user);

 method->read(&sect, sizeof(ELF_Shdr), elf_io_user, user);
 sec_table.len = (sect.sh_size%MAX_NAME_TABLE_LEN);
 sec_table.names = (char *)malloc(sec_table.len+1);
 method->seek(sect.sh_offset, elf_io_user, user);
 method->read(sec_table.names, sect.sh_size, elf_io_user, user);
 sec_table.names[sec_table.len] = 0;

 symtab.offset = 0;
 rodata.offset = 0;
 strtab.offset = 0;

 /* walk sections, save the offsets to the ones we're going to use */

 for(i = 0;i< elf_head.e_shnum; i++) {
  method->seek(elf_head.e_shoff + (i*elf_head.e_shentsize), elf_io_user,user); 
  if((elf_head.e_shoff+(i*elf_head.e_shentsize)+
       sizeof(ELF_Shdr))>size) {
   if(!quiet)
    method->error(user,"can't read %s, broken segment header\n", elf_name);
    goto fail;
  }
  method->read(&sect, sizeof(ELF_Shdr), elf_io_user, user);
#define IS_NAME(X) \
  if(strncmp(&sec_table.names[sect.sh_name%sec_table.len], X, \
     sec_table.len - (sect.sh_name%sec_table.len))==0)
  switch(sect.sh_type) {
   case SHT_NULL:
   case SHT_SHLIB:
    break;
   case SHT_SYMTAB:
    symtab.offset = sect.sh_offset;
    symtab.size = sect.sh_size;
    break;
   case SHT_STRTAB:
    IS_NAME(".strtab") {
     strtab.offset = sect.sh_offset;
     strtab.size = sect.sh_size;
    }
    break;
   case SHT_PROGBITS:
    IS_NAME(".text") {
     text.offset = sect.sh_offset;
     text.address = sect.sh_addr;
     text.index = i;
    }
    IS_NAME(".rodata") {
     rodata.offset = sect.sh_offset;
     rodata.address = sect.sh_addr;
     rodata.index = i;
    }
    break;
  }
#undef IS_NAME
 }

 if(symtab.offset == 0) {
  if(!quiet)
   method->error(user, "can't read %s, no .symtab section\n", elf_name);
   goto fail;
 }

 /* ok, now do symbol stuff */

 free(sec_table.names);

 if(strtab.offset == 0) {
  /* something I've observed but have no documentation for
   * if there's no .strtab entry .strtab is actually just
   * after symtab. If you can find docs for this mail me
   * pantsbutt@gmail.com */

  strtab.offset = symtab.offset+symtab.size;
  strtab.size = qstat.st_size - (symtab.offset+symtab.size);
 }

 if(strtab.offset > size) {
  if(!quiet)
   method->error(user,"can't open %s, .strtab out of bounds\n", elf_name);
  goto fail;
 }

 symbol_names.len = (strtab.size%MAX_NAME_TABLE_LEN);
 symbol_names.names = (char *)malloc(symbol_names.len+1);
 method->seek(strtab.offset, elf_io_user, user);
 method->read(symbol_names.names, strtab.size, elf_io_user, user);
 symbol_names.names[symbol_names.len] = 0;

 if((symtab.offset + symtab.size) > size) {
  if(!quiet)
   method->error(user,"can't open %s, .symtab out of bounds\n", elf_name);
  goto fail;
 }
 
 for(i=0;;i++) {
  if(symbol_check[i].name == (char *)0) break;
  offset = get_symbol(symbol_check[i].name, &addr, &text, &symbol_names,
             method, &symtab, &strtab, elf_io_user,
	     user, elf_name, &elf_head, size);
  if(((void *)addr != symbol_check[i].symbol) || (offset == 0)) {
   method->close(elf_io_user, user);
   free(symbol_names.names);
   goto fail;
  }
 }

 file_offset = get_symbol(SYMBOL_NAME, &addr, &rodata, &symbol_names,
                          method, &symtab, &strtab, elf_io_user,
			  user, elf_name, &elf_head, size);

 free(symbol_names.names);

 baby_io_user = method->open_baby(hint, user); 

 if((buffer = (unsigned char *)malloc(file_offset))<=0) {
  perror("copy-buffer malloc");
  exit(0);
 }

 method->seek(0, elf_io_user, user);
 method->read(buffer, file_offset, elf_io_user, user);
 method->write(buffer, file_offset, baby_io_user, user);
 free(buffer);

 method->write(newkey, sizeof(key_lump), baby_io_user, user);

 len = size - file_offset - sizeof(key_lump);
 if((buffer = (unsigned char *)malloc(len))<=0) {
  perror("copy-buffer malloc");
  exit(0);
 }

 method->seek(file_offset+sizeof(key_lump), elf_io_user, user);
 method->read(buffer, len, elf_io_user, user);
 method->write(buffer, len, baby_io_user, user);
 free(buffer);

 method->close(elf_io_user,  user);
 method->chmod(baby_io_user, user, 0111);
 method->close(baby_io_user, user);

 return 1;
fail:
 free(elf_name);
 method->error(user,"\n"
              "*********************************************************\n"
              "* failed to read elf or elf suspected not to be running *\n"
              "* binary. please specify binary location manually       *\n"
	      "*********************************************************\n");
 if((new_name = method->prompt_new_binary(user))==(char *)0)
  exit(0); 
 hint = new_name;
 elf_name = method->rehint(user, hint);
 store = concr_baby(baby_name, new_name, key_name, 
                    hint, user, newkey,method);
 return store;
}

char *concr_guessname(char *argv_0) {
 char *path;
 char *new_path;
 int path_len;
 int path_pos, i;
 int max_len;
 struct stat qstat;

 if(stat(PROC_PATH, &qstat)==0) 
  if(qstat.st_size != (off_t)0)
   return PROC_PATH; 

 max_len = strlen(argv_0);

 if(strlen(argv_0)<2) return (char *)0;

 /* type "./binary" */

 if(argv_0[0] == '.' &&
    argv_0[1] == '/') {
  if(max_len >3)
   return &argv_0[2];
  else
   return (char *)0;
 }

 /* type "/direct/path/to/binary" */
 if(argv_0[0] == '/') {
  return argv_0;
 } else {
 /* type "binary" */

  if((path = getenv("PATH"))<=0) { 
   fprintf(stderr, "PATH not defined in environment\n");
   return (char *)0;
  }
  path_len = strlen(path);
  if(path_len <2)
   return (char *)0;
  new_path = (char *)malloc(path_len + max_len + 2);
  bzero(new_path, path_len + max_len + 2);
  concr_guessname_garbage = new_path;

  i = 0;
  for(path_pos=0;path_pos<path_len;path_pos++) {
   new_path[i] = path[path_pos];
   if(new_path[i] == ':') {
    new_path[i] = '/';
    new_path[i+max_len+1]  = 0;
    memcpy(&new_path[i+1], argv_0, max_len);
    if(stat(new_path, &qstat)==0) 
     if(qstat.st_size != (off_t)0)
      return new_path;

    i = 0;
   } else
    i++;
  }
 }

 return (char *)0;
}

