
/* =====[ test5.c ]=========================================================

   Description:         Gambit challange. Compile on msys GCC. (free tools)

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.27.2017     Peter Glen      Initial version.
      0.00  aug.30.2017     Peter Glen      Generalized.

   ======================================================================= */

// Will test for combinations of random influencers.

#include <stdio.h>

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>                     

#define TRUE  (1==1)
#define FALSE (1==0)

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

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

int val[1024];
int validx = 0;

int is_sane(const char *txt);

int main(int argc, char *argv[]) 
{
    signal(SIGSEGV, myfunc);

    // Read in file
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
    
    int idx = 0; char ccc[15];
    ccc[0] = '\0';    
    for(int loop =0; loop < rsa_len; loop++)
        {
        char xx = rsa_buf[loop];
        if((xx >= '0' && xx <= '9'))
            {
            ccc[idx++] = xx;
            }
        else
            {
            if(idx)
                {
                ccc[idx++] = '\0';
                int aaa = atoi(ccc);
                //printf("%s %d - ", &ccc, aaa);
                val[validx++] = aaa;
                
                if (validx > sizeof(val) / sizeof(int))
                    xerr2("Data too big.");
                }
            idx = 0;
            }
        }
    printf("\n");
    
    //////////////////////////////////////////////////////////////////////
    srand(time(NULL));
      
    int aa = 18,  bb = 43,  cc = -14;
    char *message = malloc(validx + 10);

    for (int loop = 0; loop < 100000000; loop++)
        {    
        if(loop % 10000 == 9999)
            printf("loop %d\r", loop);

        aa = rand() % 256 - 128;
        bb = rand() % 256 - 128;
        cc = rand() % 256 - 128;
        
        //printf("aa %d bb %d cc %d\n", aa, bb, cc);
        
        int loop2 = 0;
        for (loop2 = 0 ; loop2 < validx ; loop2++) 
            {
            int val2 = val[loop2];
            if (loop2 % 3 == 0) val2  -= aa;
            if (loop2 % 3 == 1) val2  -= bb;
            if (loop2 % 3 == 2) val2  -= cc;
            message[loop2] = val2 & 0xff;
            }
        message[loop2] = '\0';    
        if(is_sane(message))
            {
            printf("aa %d bb %d cc %d\n", aa, bb, cc);
            printf("%s\n",  message);
            }
    }
    free(message);
    
    return 0;
}

//////////////////////////////////////////////////////////////////////////
// return TRUE if character str has sane stuff
// Relying on minimal sanness ...  works well
 
int is_sane(const char *txt)

{
    int ret = 0;
    
    char *txt2 = strdup(txt);
    int len2 = strlen(txt2);
    
    // Lower it
    for(int loop = 0; loop < len2; loop++)
        {
        char chh = txt2[loop];
        if(chh >= 'A' && chh <= 'Z')
            {
            chh += 32;
            txt2[loop] = chh;
            }
        }
        
    //printf("lower '%s'\n", txt2);
    
    if(strstr(txt2, " http:") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
        
    if(strstr(txt2, " tel ") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
        
    if(strstr(txt2, " for ") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
    if(strstr(txt2, "street") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
    if(strstr(txt2, "contact") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
    if(strstr(txt2, "submit") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
    
    if(strstr(txt2, " a ") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
    
    if(strstr(txt2, " the ") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
        
  endd:
    free (txt2); 
    return ret;            
}


