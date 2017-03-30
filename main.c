#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <inject.h>
#include <elf_protect.h>
#include <common.h>

int main(int argc, char **argv)
{
	void *buf,*obuf;
	unsigned int fsize=0;
	unsigned int ofsize=0;

	int i,pidx,shidx;
    FILE *fp;
    if (argc < 2)
    {
        print_help(argv[1]);
        exit(0);
    }
    
    if (strcmp(argv[1],"-h") == 0)
    {
        print_help(argv[1]);
        exit(0);
    }else if (strcmp(argv[1],"-i") == 0)
    {
        
        fp = fopen(argv[3], "rb");
        if (fp == NULL)
            error("File not exists");
	
        fseek(fp, 0L, SEEK_END);
    	fsize = ftell(fp);
    	fseek(fp, 0L, SEEK_SET);
	
    	buf = malloc(fsize+0x4000);
    	fread(buf, fsize, 1, fp);
	
    	fclose(fp);
    
    
        fp = fopen(argv[2], "rb");
    	if (fp == NULL)
    		error("File not exists");
    	
    	fseek(fp, 0L, SEEK_END);
        ofsize = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
	
    	obuf = malloc(ofsize);
    	fread(obuf, ofsize, 1, fp);
	
    	fclose(fp);
    
        fsize = injectElf32Object(buf, fsize, obuf, ofsize);

    	fp = fopen(argv[4], "wb");
		if (fp == NULL)
			return 0;
		fwrite(buf, fsize, 1, fp);
		fclose(fp);
		return 0;
        
        
    }else if (strcmp(argv[1],"-p") == 0)
    {
        	FILE *fp = fopen(argv[2], "rb");
	if (fp == NULL)
		error("File not exists");
	
	fseek(fp, 0L, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	
	buf = malloc(fsize+0x4000);
	fread(buf, fsize, 1, fp);
	
	fclose(fp);
    
	
    fsize = injectElf32Protector(buf, fsize, argv[3]);

	
	fp = fopen(argv[3], "wb");
	if (fp == NULL)
		return 0;
	fwrite(buf, fsize, 1, fp);
	fclose(fp);
	return 0;

    }else
    {
        print_help(argv[1]);
        exit(0);
    }
}

void print_help(char *fname)
{
    printf("Usage: %s <option(s)> elf-files(s)\n Inject ELF protect code to ELF executables to protect it from infection, inject ELF object to ELF executable, scan ELF file for changes\n Options are:\n -h\tDisplay this text\n -p\tInject ELF protect code\n -i\tInject ELF object to ELF executable\n",fname);
    return;
}

void error(char *str)
{
    fprintf(stderr, "Error: %s\n",str);
    exit(1);
}
