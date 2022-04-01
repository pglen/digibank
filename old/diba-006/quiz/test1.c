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

int val[256];
int validx = 0;
char decval[256];
int decidx = 0;
int freq[256] = {0};

int freqtable[] = {


688,  32, 318, 101, 235, 116, 191, 105, 165,  97, 150, 115, 
147, 111, 144, 110, 142, 114, 135, 108, 102, 100,  92,  99,  
89, 104,  79, 117,  74,  45,  71,  46, 
 71, 121,  66, 112,  61, 102,  53, 109,  52,  98,  43, 107, 
 38, 103,  29, 119,  14, 120,  13, 118,   7,  44,   7,  47, 
  7,  58,   6,  40,   6,  41,   5,  49,   4,  52,   4,  95, 
  3,  48,   3,  54,   3, 106,   3, 113,   3, 122,   3, 124, 
  2,  34,   2,  39,   2,  55,   2,  57,   1,  56,   1,  64, 
  1,  92, 

  };

char goodtable[] = {' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 
                        'l', 'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 
                        'v', 'k',  'j', 'x', 'q', 'z'
                        };
                        
char goodtable2[sizeof(goodtable) * 10] = {0};

int xidx[] = {  82, 151, 161, 58, 160, 147, 149, 155,  127,  
                158,  164,  123,  142,  143,  150,  153, 
                165, 134,  135,  136,  137  
                };

char coll[1000] = {0};
int idxcoll = 0;
            
int is_sane(const char *txt);

//////////////////////////////////////////////////////////////////////////

void main(int argc, char *argv[])

{
    signal(SIGSEGV, myfunc);
    srand(time(NULL));             
    
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
    
    // Build freqtable
    int alloclen = 0;
    int tablen = sizeof(freqtable) / sizeof(int);
    for(int loop = 0; loop < tablen; loop += 2)
        {
        alloclen += freqtable[loop + 1];
        } 
    //printf("%d\n", alloclen);
    int *randtable = malloc(alloclen * sizeof(int) + 10);
    int newidx = 0;
    for(int loop = 0; loop < tablen; loop += 2)
        {
        //printf("%d %d ",  freqtable[loop], freqtable[loop + 1]);
        for(int loop2 = 0; loop2 < freqtable[loop]; loop2++)
            {
            randtable[newidx++] =  freqtable[loop + 1];
            }
        }
        
    //for(int loop = 0; loop < newidx; loop += 1)
    //      printf("%d ", randtable[loop]);    
    
    // spew crap 
    for(int loop = 0; loop < 2000; loop += 1)
        {
        int rrr = rand() % newidx;
        printf("%c", randtable[rrr]);
        }
                
    exit(0);
            
    // Parsed, ready to go    
    int minx = 1000; int maxx = 0; int avg = 0;
    char vvv2;
    for(int loop = 0; loop < validx; loop++)
        {
        int vvv = val[loop];
        
        freq[vvv] ++;
        // Actual decrypt
        int vvv2 = vvv - 49;
        
        printf("%4d %c", vvv, vvv2); 
        decval[decidx++] = vvv2;
        
        if(loop % 10 == 9)
            printf("\n");
            
        if(minx > vvv) minx = vvv;    
        if(maxx < vvv) maxx = vvv;    
        
        avg += vvv;
        }
        
    decval[decidx++] = '\0';
    
    printf("\n");
    
    #if 0
    for(int loop = 0; loop < 256; loop++)
        {
        printf("%3d=%d  ", loop, freq[loop]);
        if(loop % 10 == 9)
            printf("\n");
        }
        
    printf("\n");
    
    for(int loop2 = 0; loop2 < 20; loop2++)
        {
        decidx = 0;
        for(int loop = 0; loop < validx; loop++)
            {
            int vvv = val[loop];
            int vvv2 = (vvv / 2 - loop2) ;
            decval[decidx++] = vvv2 & 0xff;
            }
        decval[decidx++] = '\0';
        printf("%s\n", decval);
        struct timespec ts = {0, 20000000};
        nanosleep(&ts, NULL);
        }        
    #endif
    
    printf("\n");
    
    //////////////////////////////////////////////////////////////////////
        
    decidx = 0;
    char table[256];
    memset(table, '.', sizeof(table));
    
                 
    // Do some tries
    for(int loop3 = 0; loop3 < 200000000; loop3++)
        {
        if(loop3 % 10000 == 9999)
            printf("loop3 %d\r", loop3);
            
        decidx = 0; idxcoll = 0;
        // Construct random lookup with top entries
        for(int loop4 = 0; loop4 < sizeof(xidx) / sizeof(int); loop4++)
            {
            int rrr, valve = 0;
            while(TRUE)
                {
                if(valve++ > 1000)
                   {
                   printf("Too many dups\n");
                   break;
                   }
                rrr = rand() % sizeof(goodtable); 
                //printf("rrr=%d '%c' loop4=%d tableidx=%d \n", rrr, 
                //                goodtable[rrr], loop4, xidx[loop4] & 0xff);
            
                // Check if duplicate
                int dup = FALSE;
                for(int loop5 = 0; loop5 < sizeof(table); loop5++)
                    {
                    if(table[loop5] == goodtable[rrr])
                        {
                        dup = TRUE; 
                        //printf("table[loop5] %d dup rrr=%d \n", table[loop5], rrr);
                        }
                    }
                if (!dup)
                    break;    
                }
            table[xidx[loop4] & 0xff] = goodtable[rrr];
            coll[idxcoll++] = goodtable[rrr];
            coll[idxcoll] = '\0';
            } 
            
        //printf("coll '%s'\n", coll);
        
        // Execute lookup
        for(int loop = 0; loop < validx; loop++)
            {
            int vvv = val[loop];
            int vvv2 = table[vvv];
            decval[decidx++] = vvv2 & 0xff;
            }
        decval[decidx++] = '\0';
        
        if(is_sane(decval))
            {
            printf("coll '%s'\n", coll);
            printf("%s\n", decval);
            }
        }
        
    //printf("minx=%d, maxx=%d, diff=%d avg %d\n", minx, maxx, maxx - minx, avg / validx);
} 

// return TRUE if character str has sane stuff
 
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
    
    if(strstr(txt2, "http:") > 0)
        {
        ret = TRUE;
        goto endd;     
        }
        
    if(strstr(txt2, " tel ") > 0)
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
    
    if(strstr(txt2, " A ") > 0)
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





