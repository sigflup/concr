#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include "base64.h"

#define NORMAL 	0	
#define END	1
#define DONE	3

const char base64_alphabet[] = { 
 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};


const char *start_block = "-----BEGIN CONFCRYPT CONFIG-----\n";
const char *end_block   = "-----END CONFCRYPT CONFIG-----\n";



void (*base64_out64_callback)(char in);
void (*base64_inbyte_callback)(unsigned char in);

unsigned char base64_pos; 
unsigned char base64_pos2;
unsigned int base64_pos3;
unsigned char base64_nibble;
unsigned int base64_wrap;
uint32_t base64_quad;
unsigned char base64_phase;

void base64_reset(void) {
 base64_pos = 0;
 base64_pos2 = 0;
 base64_pos3 = 0;
 base64_nibble = 0; 
 base64_quad = 0;
 base64_phase = NORMAL;
}

void base64_outbit(char in) {
 if(base64_pos == 0)
  base64_nibble = (in&1)<<5;
 else
  base64_nibble |= (in&1)<<(5-base64_pos);
 base64_pos++;
 if(base64_pos==6) {
  base64_out64_callback(base64_alphabet[base64_nibble%64]);
  base64_nibble = 0;
  if(base64_wrap!=0) {
   base64_pos2++;
   if(base64_pos2 == base64_wrap) { 
    base64_out64_callback('\n');
    base64_pos2 = 0;
   }
  }
  base64_pos = 0;
 }
}

void base64_outbyte(int in) {
 int i;
 if(in==-1) {
  if( (base64_pos3 %3)!=0 ) {
  if(base64_nibble!=0)
   base64_out64_callback(base64_alphabet[base64_nibble%64]);
  base64_out64_callback('=');
  if((base64_pos3 %3)==1)
   base64_out64_callback('='); 
  }
  return;
 }

 base64_pos3++;
 for(i=0;i<8;i++)
  base64_outbit(((in&0xff)>>(7-i))&1); 
}

void base64_quad2triple(int len) {
 int i;
 unsigned char triple[3];

 triple[0] = ((base64_quad&0xff)&0x3f)<<2;
 triple[0]|= (((base64_quad>>8)&0xff)&0x30)>>4;
 triple[1] = (((base64_quad>>8)&0xff)&0x0f)<<4;
 triple[1]|= (((base64_quad>>16)&0xff)&0x3c)>>2;
 triple[2] = (((base64_quad>>16)&0xff)&0x03)<<6;
 triple[2]|= (((base64_quad>>24)&0xff)&0x3f);

 for(i=0;i<len;i++)
  base64_inbyte_callback(triple[i]);

 base64_quad = 0;
}

void base64_in64(int in) {
 int i;

 switch(base64_phase) {
  case DONE:
   return;
  case NORMAL:
   switch(in) {
    case -1:
     base64_phase = DONE;
     return;
    case '\n':
    case '\r':
     return;
    case '=':
     base64_phase = END;
     break;
    default:
     for(i=0;i<64;i++)
      if(base64_alphabet[i] == in) break; 
     base64_quad |= ((i&0x3f)<<((base64_pos%4)*8));
     base64_pos++;
     if((base64_pos%4)==0) 
      base64_quad2triple(3);
     break;
   }
   break;
  case END:
   switch(in) {
    case '\r':
    case '\n':
     break;
    case -1:
     base64_quad2triple(2);
     base64_phase = DONE;
    default:
     base64_quad2triple(3-(base64_pos%4));
     base64_phase = DONE;
     break;
   }
   break;
 }

 return;
}
