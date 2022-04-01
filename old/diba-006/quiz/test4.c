#include <stdio.h>

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);
    
    return  file_len;
}

int val[256];
int validx = 0;

char decval[256];
int decidx = 0;

int freq[256] = {0};

void main(int argc, char *argv[])

{
    FILE* lockf = fopen(argv[1], "rb");
    if (!lockf) {
        xerr2("dibadecrypt: Cannot open keyfile '%s'.", argv[1]);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    //zline2(__LINE__, __FILE__);
    char* rsa_buf = malloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr2("dibadecrypt: Cannot allocate rsa buffer.");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr2("dibadecrypt: Cannot read public key.");
    }
    rsa_buf[rsa_len] = '\0';
    fclose(lockf);
     
    int minx = 1000; int maxx = 0; int avg = 0;
    char vvv2;
    for(int loop = 0; loop < rsa_len; loop++)
        {
        int vvv = rsa_buf[loop];
        freq[vvv] ++;
        }
    
    for(int loop = 0; loop < 256; loop++)
        {
        printf("%3d = %-2d  ", loop, freq[loop]);
        if(loop % 10 == 9)
            printf("\n");
        }
        
    printf("\n\n");
    
    for(int loop = 0; loop < 256; loop++)
        {
        //printf("loop %d ", loop);
        int maxf = 0; int idxf = 0;
        for(int loop2 = 0; loop2 < 256; loop2++)
            {
            int ifreq = freq[loop2];
            if(ifreq > maxf)
                {
                maxf = ifreq;
                idxf = loop2;
                //printf("assigned %d %d", maxf, loop2);
                }
            }
        // Now we have the maxx and location
        if(maxf == 0)
            break;
            
        int idxf2 = idxf;
        if(idxf2 == '\n') idxf2 = '.';
        if(idxf2 == '\r') idxf2 = '.';
        printf("%3d = %-3d (%c) ", maxf, idxf, idxf2);
        if(loop % 6 == 5)
            printf("\n");
        
        
        // erase it ...    
        freq[idxf] = 0;    
        }
    printf("\n");
  
} 









             



