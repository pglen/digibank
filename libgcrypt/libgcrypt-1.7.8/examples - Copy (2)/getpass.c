
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <string.h>
#include <conio.h>

#include "getpass.h"

#define TRUE  (1==1)
#define FALSE (1!=1)

#define CRTL_C     '\3'
#define CRTL_D     '\4'
#define BACKSPACE  '\b'


// Strenghts:
//     Every item kind adds two points. (upper, lower, number, punct)

static int getstrength(const char *pass)
{
    int ret = 0;
    if(strpbrk((char*)pass, "1234567890"))
        {
        //printf("number token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "abcdefghijklmnopqrstuvwxyz"))
        {
        //printf("lowercase token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        {
        //printf("uppercase token\n");
        ret += 2;
        }
    // Incomplete, re visit on finaliation
    if(strpbrk((char*)pass, "*&!@#$%^&*()_+"))
        {
        //printf("punctuation token\n");
        ret += 2;
        }
    return ret;
}


char *getpass(const char *prompt, char *ppp, int maxlen)

{
    unsigned int idx = 0;
    ppp[idx] = 0;
    
    printf("%s ", prompt);
    fflush(stdout);
    
    while(TRUE) {
        unsigned char cc = _getch(); 
        
        //printf(" '%c' %d ", cc, cc & 0xff);
        if(cc == 224 || cc == 0)
            {
            _getch();  // Throw away
            continue;
            }    
    
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
            
        if (cc == BACKSPACE)
            {
            //printf("backspace\n");
            if(idx > 0)
                {
                idx--;
                ppp[idx] = '\0';
                putchar('\b'); putchar(' '); 
                putchar('\b');    
                }
            }
        else
            {
            ppp[idx] = cc;
            ppp[idx + 1] = '\0';
            putchar('*');    
            idx ++;
            }
        
        if (idx >= maxlen)
            break;
        }          
    //printf("got pass '%s'\n", ppp);  
    printf("\n");    
    return ppp;
}

//////////////////////////////////////////////////////////////////////////
// Get pass

int getpass2(char *pass, int maxlen, int weak, int nodouble)

{   
    int ret = (TRUE);
    int try = 0;
    const size_t keylen = 16;

    if(maxlen == 0)
        return -1;
        
    char ppp[MAXPASSLEN + 1];
    char ppp2[MAXPASSLEN + 1];
    
    while((TRUE))
        {
        getpass("Keypair Password: ", ppp, MAXPASSLEN);
            
        if(try++ >= ALLOW_TRIES)
            {
            printf("Too many tries, giving up\n");
            ret = -1;
            return ret;
            }
        
        if(!weak)
            {
            if(strlen(ppp) < MINPASSLEN)
                printf("Must be %d characters or more, try again.\n", MINPASSLEN);
            else if(getstrength(ppp) < 6)
                printf("Pass must have upper and lower case letters and numbers, try again.\n");
            else
                break;
            }
        else
            {
            if(strlen(ppp) <= 0)
                printf("Cannot use empty pass, try again.\n");
            else
                break;
            }
        }
        
    if(nodouble == FALSE)
        {
        int try2 = 0;
        while((TRUE))
            {
            getpass("Confirm Password: ", ppp2, MAXPASSLEN);
            if(strcmp(ppp, ppp2) == 0)
                break;
            
            if(try2++ >= ALLOW_TRIES)
                {
                printf("Too many tries, giving up\n");
                ret = -1;
                break;
                }
            printf("Passes do not match, try again.\n");
            }
         }
    if(ret == (TRUE))
        {
        strncpy(pass, ppp, maxlen);
        }
    
    //if (pass_len == 0) {
    //    //xerr("getpass: not a valid password");
    //    printf("getpass warning: empty password.\n");
    //}
    
    return ret;
}








