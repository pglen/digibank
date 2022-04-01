
/* =====[ test_zstr.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdline.h"
#include "zmalloc.h"
#include "base64.h"
#include "misc.h"
#include "zstr.h"


int main(int argc, char** argv)
                                        
{
    char    *res = zstrmcat(MAX_PATH, "aa", "bb", "cc", NULL);
    printf("result: %s\n", res);
    zfree(res);
    zleak();  
}












