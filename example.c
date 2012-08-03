#include <stdio.h>
#include <sys/stat.h>

#include <concr/concr.h>

int 
example_decrypt_input(char *in, int len)
{
	return fread(in, 1, len, stdin);
}

int 
example_decrypt_eof(void)
{
	return feof(stdin);
}

int 
main(int argc, char **argv)
{
	int             l;
	char            dat;
	if (argc == 0)
		return 0;
	working_key = concr_getkey(NULL, concr_guessname(argv[0]));

	concr_decrypt_input = example_decrypt_input;
	concr_decrypt_eof = example_decrypt_eof;

	decode_init();

	while ((l = concr_rd(&dat, 1)) != -1)
		if (l == 1)
			putchar(dat);

	return 1;
}
