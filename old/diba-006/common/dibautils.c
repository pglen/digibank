
/* =====[ dibautils.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.22.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "dibautils.h"

#include "diba.h"
#include "bluepoint3.h"
#include "gcry.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"

// Generate random buffer in place. Favour none.

void    rand_buff(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len; loop++)
        {
        str[loop] = rand() % 255;
        }
}

// Generate random string in place. Favour lower case letters.

void    rand_asci_buff(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len; loop++)
        {
        //str[loop] = rand() % 255;
        
        // Favour lower case letters
        int ttt = rand() % 6;
        if (ttt == 0)
            str[loop] = (rand() % 10) + '0';
        else if (ttt == 1)
            str[loop] = (rand() % 26) + 'A';
        else
            str[loop] = (rand() % 26) + 'a';
        }
}

void rand_str(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len - 1; loop++)
        {
        // Favour lower case letters
        int ttt = rand() % 8;
        if (ttt == 0)
            str[loop] = (rand() % 10) + '0';
        else if (ttt == 1)
            str[loop] = (rand() % 26) + 'A';
        else
            str[loop] = (rand() % 26) + 'a';
        }
   str[loop] = '\0';
}

void    show_str_lines(const char* str, int len)

{
    int linelen = 34;
    for(int loop = 0; loop < len; loop++)
        {
        printf("%02x", str[loop] & 0xff);
        if((loop % linelen) == linelen - 1)
            printf("\n");
        }
}   

void    show_str(const char* str, int len)

{
    int olen = 3 * len;
    char *ptr = zalloc(olen);
    bluepoint3_tohex((char*)str, len, ptr, &olen);
    printf("%s", ptr);
    zfree(ptr); 
}   

int     str_fromhex(char *str, int len, char *str2, int *olen)

{
    char sss[4]; int idx = 0, idx2 = 0;
    for(int loop = 0; loop < len; loop++)
        {
        long nn;
        char chh = str[loop];
        if((chh >= '0' && chh <= '9') ||
                (chh >= 'a' && chh <= 'f') ||
                    (chh >= 'A' && chh <= 'F') )
            {
            sss[idx++] = chh;
            if(idx >= 2)
                {
                sss[idx] = '\0';
                nn = strtol(sss, NULL, 16);
                str2[idx2++] = nn & 0xff;
                idx = 0;
                }
            }
        }
    str2[idx2] = '\0';
    *olen = idx2;
    return 0;
}

//void show_hexstr(const char* str, int len)
//
//{
//    char *str2 = bluepoint3_dumphex(str, len);
//    printf("%s\n", str2);
//}   

//////////////////////////////////////////////////////////////
// Reverse string in place

void    genrev(char *str, int len)

{
    int loop, bb;
    
    if (len <= 10)
        {
        printf("Must have more than 10 bytes\n");
        return;
        }
    
    // Init beginning
    //for (bb = 0; bb < 8; bb++)
    //    str[bb] = '\0';
        
    // Count up
    for(loop = len-(ASIZE+1); loop >= ASIZE; loop--)
        {
        UCHAR cc = str[loop];
        if(cc == 0xff)
            {
            str[loop] = 0;
            }
        else
           {
           str[loop] = ++cc;
           break;
           }
        }
}

char *diba_alloc(int size)

{
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(size); 
    
    if(ret == NULL) 
        {
        fprintf(stderr, "%s\n", mstr);
        exit(2);
        }
        
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Build next sexp

int  build_next(gcry_sexp_t *chain_next, build_next_struct *bns)

{
    int err = gcry_sexp_build(chain_next, NULL, 
                "(\"Next Work\" (\"Next Calc Date\" %s) "
                    "(\"Next Hash\" %s) (\"Next Padding\" %s) (\"Next ID\" %s) "
                    "(\"Next File\" %s) (\"Next Work Hash\" %s) )",
                    bns->next_calc, bns->next_hash, bns->next_pad,
                        bns->next_id, bns->next_file, bns->next_workhash) ;
    return err;                            
}

// Read in and decode file to sexp

int     read_sexp_from_file(const char *fname, gcry_sexp_t *sexp, char **err_str)

{
    int ret = 0, glen;  gcry_error_t err = 0;
    *err_str = NULL;

    char  *back = grabfile(fname, &glen, err_str);
    if(*err_str)
        {
        //xerr2("%s '%s': %s\n", err_str3, fname, strerror(errno));
        return 0;
        }
    //printf("%s\n", back);
     
    char *start2;
    int len5 = frame_buff(back, &start2);
    if(!len5 || !start2)
        {
        *err_str = "Cannot frame (invalid file syntax";
        return 0;
        }
    int xlen;
    char *ub = unbase_and_unlim(start2, len5, &xlen);
    //printf("'%s\n", ub);
    zfree(back);
    
    gcry_sexp_t backsexp;
    err = gcry_sexp_new(sexp, ub, xlen, 1);
    zfree(ub);
    if (err) 
        {
        //xerr2("Failed to decode back key sexp. %s\n", gcry_strerror (err));
        *err_str = "Failed to decode sexp.";
        return 0;
        }
   return 1;       
}

//////////////////////////////////////////////////////////////////////////

int     write_sexp_to_file(const char *fname, gcry_sexp_t *sexp, char **err_str)

{
    int plen, blen;
    *err_str = NULL;
    
    zline2(__LINE__, __FILE__);
    char    *buff = sexp_get_buff(*sexp, &plen);
    if(!buff)
        {
        *err_str = "Cannot alloc sexo decode memory\n";  return 0;
        }
    char    *lim = base_and_lim(buff, plen, &blen);
    zfree(buff);
    if(!lim)
        {
        *err_str = "Cannot alloc base and lim memory\n";  return 0;
        }
    char    *cat2 = zstrmcat(0, chain_start, "\n", lim, "\n", chain_end, "\n", NULL); 
    zfree(lim);
    if(!cat2)
        {
        *err_str = "Cannot alloc memory\n";  return 0;
        }
    putfile(fname, cat2, strlen(cat2), err_str);
    zfree(cat2); 
    if(*err_str)
        {
        //xerr2("%s '%s': %s\n", err_str4, fname, strerror(errno));
        return 0;
        }
    return 1;
}











