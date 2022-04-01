
/* =====[ test_base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <string.h>

#include "zmalloc.h"
#include "base64.h"

int main(int argc, char** argv)
{
    //printf("Testing base64\n");
    
    const unsigned char* sss = (const unsigned char*)
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. ";

    //zverbose(1);
     
    printf("org:\n'%s'\n", sss);
    int slen =  strlen(sss);
    int outlen = base64_calc_encodelen(slen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen);
    base64_encode(sss, slen, mem, &outlen);
    printf("base64 outlen=%d\n'%s'\n", outlen, mem);                                           
    zcheck(mem, __LINE__);             
    zline2(__LINE__, __FILE__);
    
    int linelen = 64;
    int limlen = outlen + 4 + outlen / linelen ;
    char *mem3 = zalloc(limlen);        
    base64_limline(mem, outlen, mem3, &limlen, linelen);
    printf("base64 expand limlen=%d\n'%s'\n", limlen, mem3);                                           
    
    int ulimlen = limlen;
    char *mem4 = zalloc(ulimlen);        
    int ret = base64_clean(mem3, limlen, mem4, &ulimlen);
    printf("base64 unexpand ulimlen=%d\n'%s'\n", ulimlen, mem4);                                           
    
    int declen = base64_calc_decodelen(ulimlen);
    zline2(__LINE__, __FILE__);
    char *dmem = zalloc(declen);
    base64_decode(mem4, ulimlen, dmem, &declen);
    printf("dec base64\n'%s'\n", dmem);
    //dump_mem(dmem, strlen(dmem));
    zline2(__LINE__, __FILE__);
    zcheck(dmem, __LINE__);
    
    zline2(__LINE__, __FILE__);
    zfree(mem);
    zfree(dmem);
    zfree(mem3);
    zfree(mem4);
    
    zleak();  
}




