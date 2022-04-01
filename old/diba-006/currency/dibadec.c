
/* =====[ dibadec.c ]=========================================================

   Description:     Feasability study for diba. Decode generated number.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.11  nov.06.2017     Peter Glen      Currency started

   ======================================================================= */

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "bluepoint3.h"
#include "diba.h"
#include "dibastr.h"
#include "dibautils.h"
#include "cmdline.h"
#include "zmalloc.h"

static  void  decode(char * str, int len);

// Replace bsize for testing 
#undef BSIZE
#define BSIZE 512

unsigned char str[4 * BSIZE]; 
unsigned char str2[4 * BSIZE]; 

//////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    unsigned int  loop;
    
    if (argc < 2)
        {
        fprintf(stderr, "Must specify string to decrypt / check.\n");
        exit(0);    
        }
    if (strcmp(argv[1], "-") == 0)
        {
        //printf("Reading stdin");
        int idx = 0;
        while (TRUE)
            {
            char chh;
            int len = fread(&chh, sizeof(chh), 1, stdin); 
            if(len == 0)
                break;
            if(idx >= sizeof(str))
                break;
            str[idx++] = chh;    
            }
        str[idx] = '\0';
        printf("Original: (%d len)\n'%s'\n", idx, str);
        decode(str, idx);
        exit(0);
        }
    for(loop = 1; loop < argc; loop++)
        {   
        strncpy(str, argv[loop], sizeof(str)); int len = strlen(str);
        if (len > sizeof(str)) len = sizeof(str);
        //printf("org: len %d\n%s\n", len, str);
        decode(str, len);
        }
    exit(0);
}

void  decode(char *str, int len)

{
    int olen = len;
    char *mem = zalloc(len + 1);
    str_fromhex(str, len, mem, &olen);
    printf("undumped: \n");
    show_str(mem, olen); 
    printf("\n\n");
    
    bluepoint3_set_rounds(BSIZE / 6);
    bluepoint3_decrypt(mem, olen, dibapass, strlen(dibapass));
    int olen2 = 3 * olen;
    char *dec  = zalloc(olen2);
    bluepoint3_tohex(str2, olen, dec, &olen2);
    
    printf("Decoded:\n%s\n", dec);
}

/* EOF */




























