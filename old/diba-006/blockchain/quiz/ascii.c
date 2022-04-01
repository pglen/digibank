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

void main(int argc, char *argv[])

{
    for(int loop = 32; loop < 128; loop++)
        {
        printf("%4d  %c ", loop, loop); 
        
        if((loop - 32) % 10 == 9)
            printf("\n");
        }
        
} 









             
