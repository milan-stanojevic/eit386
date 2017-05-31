#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include <inject.h>
#include <common.h>


/*
Usage:
Add ELF protector to ELF executable
./eit386 -p input_elf output_elf
Inject object file to to ELF executable
.eit386 -i object_file input_executable output_executable
*/

int main(int argc, char **argv)
{

	void *buf,*obuf;
    unsigned int fsize=0;
    unsigned int ofsize=0;

    FILE *fp;
    if (argc < 2)
    {
        print_help(argv[0]);
        exit(0);
    }

    if (strcmp(argv[1],"-h") == 0)
    {
        print_help(argv[0]);
        exit(0);
    } else if (strcmp(argv[1],"-i") == 0 && argc == 5)
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
            error("Can not create output file");
        fwrite(buf, fsize, 1, fp);
        fclose(fp);
   	chmod(argv[4], 0x1FD);

        return 0;


    } else if (strcmp(argv[1],"-p") == 0 && argc == 4)
    {
        FILE *fp = fopen(argv[2], "rb");
        if (fp == NULL)
            error("File not exists");

        fseek(fp, 0L, SEEK_END);
        fsize = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        buf = malloc(fsize+0x4000);
        memset(buf,fsize+0x4000,0);
        fread(buf, fsize, 1, fp);

        fclose(fp);
		
        fsize = injectElf32ProtectionObject(buf, fsize);
		

        fp = fopen(argv[3], "wb");
        if (fp == NULL)
            error("Can not create output file");
        
		fwrite(buf, fsize, 1, fp);
        fclose(fp);
		
		chmod(argv[3], 0x1FD);

        return 0;

    } else
    {
        print_help(argv[0]);
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
