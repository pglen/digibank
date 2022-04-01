
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug03.2017     Peter Glen      Initial version.

   ======================================================================= */
 
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"
#include "misc.h"

//////////////////////////////////////////////////////////////////////////
// Print sexp to memory
// Free the resulting pointer with zfree

char *sprint_sexp(gcry_sexp_t sexp, int *len, int format)

{
    int slen = gcry_sexp_sprint(sexp, format, NULL, 0);
    *len = 0;
    zline2(__LINE__, __FILE__);
    char *ppp = (char*)zalloc(slen+1);
    if(ppp == NULL)
        return NULL;
    
    gcry_sexp_sprint(sexp, format, ppp, slen);
    *len = slen;
    // Zero terminate
    ppp[slen-1] = '\0';
    return(ppp);
}    

//////////////////////////////////////////////////////////////////////////
// Print sexp to stdout

void print_sexp(gcry_sexp_t rsa_keypair)

{
    int len;
    char *ppp = sprint_sexp(rsa_keypair, &len, GCRYSEXP_FMT_ADVANCED);
    if(ppp == NULL)
        return;
    printf("%s\n", ppp);
    zfree(ppp);
}    

int print_mem(char *mem, int len)

{
    printf("print mem %d len\n", len);
    for(int loop = 0; loop < len; loop++)
        printf("%c", mem[loop]);
    return 0;
}

void dump_mem(const char *ptr, int len)

{
    int loop, cut = 16, base = 0;
    
    if (ptr == NULL) 
        {
        printf("NULL\n");
        return;
        }
        
    printf("Begin: %p (len=%d)\n", ptr, len);
    while(1==1)
        {
        printf("%4d   ", base);
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                printf("%.02x", ptr[base + loop] & 0xff);
                if(loop < 15)
                    printf("-");
                }
            else
                {
                printf("  ");
                if(loop < 15)
                    printf(" ");
                }
            }
        printf("   ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                unsigned char chh = ptr[base + loop] & 0xff;
                if(chh < 128 && chh >= 32 )
                    printf("%c", chh);
                else
                    printf(".");
                }
            else
                printf(" ");
            }
        printf("\n");
        base += 16;
        if(base >= len)
            break;
        }
    printf("End\n");
}    

static int decode_one(gcry_sexp_t list, const char *findstr)

{
    int len = 0, onelen = gcry_sexp_length(list);
    
    for(int loop = 0; loop < onelen; loop++)
        {
        const char *data = gcry_sexp_nth_data(list, loop, &len);
        if (data == NULL)
            decode_sexp(gcry_sexp_cdr(list), findstr);
        else
            {
            if(strncmp(findstr, data, len) == 0)
                {
                const char *data2 = gcry_sexp_nth_data(list, loop + 1, &len);
                if (data == NULL)
                    return 0;
                //printf("data%d '%.*s'\n", len, len, data);
                //dump_mem(data, len);
                }
            }
        }
}    

int decode_sexp(gcry_sexp_t list, const char *findstr)

{
    int ret = 0;
    
    for (int loop = 0; loop < gcry_sexp_length(list); loop++)
        {
        gcry_sexp_t element = gcry_sexp_nth(list, loop);
        //printf("element start\n");
        //print_sexp(element);
        //printf("\nelement end\n");
        decode_one(element, findstr);
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get sexp as a buffer
// Free return value with zfree

char    *get_sexp_buff(gcry_sexp_t sexp, int *plen)

{
    char *ret = NULL;
    int len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
    zline2(__LINE__, __FILE__);
    ret = zalloc(len + 1);    
    *plen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, ret, len);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get a list ot an element, zero terminated
// Must free pointer with zfree

char    *sexp_nth_data(gcry_sexp_t  element, int num, int *plen)

{
    char *ret;
    const char *buff = gcry_sexp_nth_data(element, num, plen);
    zline2(__LINE__, __FILE__);
    ret = zalloc(*plen + 1);
    if(ret != NULL)
        {
        memcpy(ret, buff, *plen);
        ret[*plen] = '\0';    
        }
    return ret;
}
    
//////////////////////////////////////////////////////////////////////////
// Return a base64 encoded hash string

char *hash_sexp(gcry_sexp_t pubk, int *olen)

{
    int klen;
    char pub_hash[32];
    char *kptr = sprint_sexp(pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
        xerr2("sprint failed. %s %d", __FILE__, __LINE__);                                                              
    }
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash, 
                        (const void*) kptr, klen);
    zfree(kptr);                                    
    char *hash_str = base_and_lim(pub_hash, sizeof(pub_hash), olen);
    
    return hash_str;
}

//////////////////////////////////////////////////////////////////////////
// List sexpr to console
// Return the number of items printed

int list_sexp(gcry_sexp_t list)

{
    int ret = 0;
    printf("\n");
    for (int loop = 1; loop < gcry_sexp_length(list); loop++)
        {
        gcry_sexp_t element = gcry_sexp_nth(list, loop);
        
        unsigned int plen;
        char *buff = sexp_nth_data(element, 0, &plen);
        unsigned int plen2;
        char *buff2 = sexp_nth_data(element, 1, &plen);
        printf("%-20s - '%s'\n", buff, buff2);
        zfree(buff); zfree(buff2);
        ret++;
        }
    printf("\n");
    return ret;
}

char *dohex(char *mem, int len, int *olen)

{
    zline2(__LINE__, __FILE__);
    char *ptr = zalloc(3*len);
    if(ptr == NULL)
        return ptr;
    int prog = 0;
    for(int loop = 0; loop < len; loop++)
        {
        prog += sprintf(ptr + prog, "%02x", mem[loop] & 0xff);
        }
    ptr[prog] = '\0';    
    *olen = prog;    
    return ptr;               
}

char *dounhex(char *mem, int len, int *olen)

{
    //printf("dounhex %s %p %d len\n", mem, mem, len);
    zline2(__LINE__, __FILE__);
    char *ptr = zalloc(3*len);
    if(ptr == NULL)
        return ptr;
    int prog = 0;
    for(int loop = 0; loop < len; loop+= 2)
        {
        int cch, cchh;
        sscanf(mem + loop, "%02x", &cch);
        ptr[prog] = (char)(cch & 0xff);
        prog++;
        }
    *olen = prog;    
    //printf("dounhex %p %d len\n", mem, len);
    return ptr;               
}

/* EOF */











