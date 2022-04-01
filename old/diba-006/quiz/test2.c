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

    //printf("\n'%s'\n", rsa_buf);

    int minx = 1000; int maxx = 0; int avg = 0;
    for(int loop = 0; loop < rsa_len; loop++)
        {
        char vvv = rsa_buf[loop];
        char vvv2 = vvv;
        freq[vvv] ++;
        
        if (vvv2 == '\n') vvv2 = ' ';
        //printf("%4d %c", vvv, vvv2);
        
        //if(loop % 10 == 9)
        //    printf("\n");
            
        if(minx > vvv) minx = vvv;    
        if(maxx < vvv) maxx = vvv;    
        avg += vvv;
        }
    printf("\n");       
    int cnt = 0;
    for(int loop = 0; loop < 256; loop++)
        {
        if(freq[loop])
            {
            printf("%d '%c'=%3d  ", loop, loop, freq[loop]);
            if(cnt % 8 == 7)
                printf("\n");
            cnt++;
            }
        }
    printf("\n");       
    printf("minx=%d, maxx=%d, diff=%d avg %d\n", minx, maxx, maxx - minx, avg / rsa_len);
} 









             



