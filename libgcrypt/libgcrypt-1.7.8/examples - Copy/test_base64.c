
/* =====[ main.c ]=========================================================

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
    
    const unsigned char* s = (const unsigned char*)
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. ";

    printf("org:\n'%s'\n", s);

    int outlen = base64_calc_encodelen(strlen(s));
    zline(__LINE__);
    char *mem = zalloc(outlen);
    base64_encode(s, strlen(s), mem, &outlen);
    printf("base64\n%s\n", mem);                                           
    zcheck(mem, __LINE__);
    zline(__LINE__);
    
    int declen = base64_calc_decodelen(outlen);
    zline(__LINE__);
    char *dmem = zalloc(declen);
    base64_decode(mem, outlen, dmem, &declen);
    printf("dec base64\n'%s'\n", dmem);
    //dump_mem(dmem, strlen(dmem));
    zcheck(dmem, __LINE__);
    zline(__LINE__);
    
    zfree(mem);
    zfree(dmem);
    
    zleak();  
}

