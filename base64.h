extern unsigned int base64_wrap;

void (*base64_out64_callback)(char in);
void (*base64_inbyte_callback)(unsigned char in);

void base64_reset(void);
void base64_outbyte(int in); 
void base64_in64(int in);

extern const char *start_block;
extern const char *end_block;
