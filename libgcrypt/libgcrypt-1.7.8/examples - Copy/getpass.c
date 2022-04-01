
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include "conio.h"
#include "getpass.h"

#define MAXPASSLEN 512
#define CRTL_C     '\3'
#define CRTL_D     '\4'

char *getpass(const char *prompt, char *ppp, int maxlen)

{
    unsigned int idx = 0;
    ppp[idx] = 0;
    
    printf("%s ", prompt);
    fflush(stdout);
    
    while(1==1) {
        char cc = _getch(); 
            
        if (cc == '\n')
            break;
        if (cc == '\r')
            break;
        if (cc == EOF)
            break;
        if (cc == CRTL_C)
            break;
        if (cc == CRTL_D)
            break;
            
        ppp[idx] = cc;
        ppp[idx + 1] = '\0';
        putchar('*');    
        idx ++;
        if (idx >= maxlen)
            break;
        }          
    //printf("got pass '%s'\n", *ppp);  
    printf("\n");    
    return ppp;
}



