
/* =====[ test_base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.04.2017     Peter Glen      Terminator added

   ======================================================================= */

#include <stdio.h>
#include <string.h>

#include "zmalloc.h"
#include "base64.h"

int main(int argc, char** argv)
{
    //printf("Testing base64.\n");
    //char str[] = "Here is a nul string.\0Null.";
    //printf(" '%s' '%*s'\n", str, sizeof(str), str);
    //return(0);
    
    const unsigned char* sss = (const unsigned char*)
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";
    
    //zverbose(1);
     
    printf("org: len=%d\n'%s'\n\n", strlen(sss), sss);
    int slen =  strlen(sss);
    int outlen = base64_calc_encodelen(slen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen + 1);
    //printf("base64 encode pre outlen=%d\n", outlen);                                           
    base64_encode(sss, slen, mem, &outlen);
    mem[outlen] = '\0';
    printf("base64 encode outlen=%d\n'%s'\n", outlen, mem);                                           
    zcheck(mem, __LINE__);             
    
    int dlen2 = outlen;
    char *dmem2 = zalloc(dlen2 + 1);
    base64_decode(mem, outlen, dmem2, &dlen2);
    printf("base64 decode dlen=%d\n'%s'\n", dlen2, dmem2);                                           
    zcheck(mem, __LINE__);             
    
    if (strcmp(sss, dmem2) != 0)
        {
        printf("\nError! Decode does not match\n");
        }
    zfree(mem); zfree(dmem2);
    
    zleak();  
}








