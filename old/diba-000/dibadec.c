
/* =====[ dibagen.c ]=========================================================

   Description:     Feasability study for dibadec.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.

   ======================================================================= */

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <curses.h>

#include "diba.h"
#include "bluepoint2.h"

void  decode(char * str, int len);

UCHAR str[4 * BSIZE]; UCHAR str2[4 * BSIZE]; 

int    main(int argc, char *argv[])

{
    UINT  loop;
    
    if (argc < 2)
        {
        fprintf(stderr, "Must specify string to decrypt / check.\n");
        exit(0);    
        }

    if (strcmp(argv[1], "-") == 0)
        {
        //printf("Reading stdin");
        while (TRUE)
            {
            fgets(str, sizeof(str), stdin); 
            if(str[0] == 0) break;
            decode(str, strlen(str));
            }
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

void  decode(char * str, int len)

{
    char *ud = bluepoint2_undump(str, len);
    memcpy(str2, ud, len/2);
    //bluepoint2_dump(str2, len/2); printf("%s\n", ud);
    bluepoint2_decrypt(str2, len/2, pass, sizeof(pass));
    char *dec  = bluepoint2_dump(str2, len/2);
    printf("%s\n", dec);
}

/* EOF */




















