
/* =====[ dibagen.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.
      0.10  Jul.04.2017     Peter Glen      Initial version.

   ======================================================================= */

// DibaGen 

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "bluepoint3.h"
#include "diba.h"
#include "dibautils.h"
#include "cmdline.h"

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  batch = TRUE;
static int  verbose = FALSE;
static int  test = FALSE;

/*typedef struct _opts
{
    char    opt;
    char    *long_opt;
    int     *val;
    char    **strval;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts */

opts opts_data[] = {
                    'n',   "--number",  &entries, NULL, 0, 0xffff, NULL, 
                    "-n[num] --number  - number of entries to generate defaults to 1, range(1-16M)",
                    's',    "--skip", &skip,  NULL, 0, 0xffff, NULL, 
                    "-s[num] --skip    - number of entries to skip defaults to 0, range(1-16M)",
                    'm',    "--mode", &skip, NULL, 0, 0xffff, NULL, 
                    "-m[num] --mode    - Mode of generation, defaults to 0, range(0-255)",
                    'v',   "--verbose",  NULL,  NULL, 0, 0, &verbose, 
                    "-v      --verbose - Verbosity on",
                    't',    "--test", NULL, NULL,  0, 0, &test, 
                    "-t      --test    - test on",
                     0,     NULL,  NULL, NULL,     0, 0,  NULL, NULL,
                    };

char pass[] = "1234";

// Protected strings
UINT bound = 0x41424344;
UCHAR str[BSIZE]; 
UINT bound2 = 0x42434445;
UCHAR str2[BSIZE]; 
UINT bound3 = 0x43444546;


int    main(int argc, char *argv[])

{
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage("dibagen [options]", "Generate DIBA hashes.", opts_data); exit(2);
        }
    
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaGen written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    
    UINT  loop;
    
    //bluepoint3_set_verbose(TRUE);
    //bluepoint3_set_rounds(3);
    
    // Init string
    for (loop = 0; loop < sizeof(str); loop++)
        {
        str[loop] = (UCHAR)mode; 
        }
    for(loop = 0x0; loop < entries;  loop++)
    //for(loop = 0x0; loop < 0x3;  loop++)
        {
        genrev(str, sizeof(str));
        
        if (loop >= skip)
            {
            if (test) {
                printf("Original:\n");
                show_hexstr(str, sizeof(str));
            }
            
            memcpy(str2, str, sizeof(str2));
            bluepoint3_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
            if (test)
                printf("Encrypted:\n");
            show_hexstr(str2, sizeof(str2));
            printf("\n");
    
            // Verify
            if (test) {
                bluepoint3_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
                if (test)
                    printf("Derypted:\n");
                show_hexstr(str2, sizeof(str2));
                printf("\n");
                
                 if (memcmp(str, str2, sizeof(str2)))
                    {
                    printf("Bad decription!\n\n");
                    }        
                   
                // Verify mutation
                printf("Mutate: (may not match)\n");
                memcpy(str2, str, sizeof(str2));
                //show_hexstr(str2, sizeof(str2));
        
                bluepoint3_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
                str2[2] = str2[2] + 1;
                show_hexstr(str2, sizeof(str2));
                bluepoint3_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
                printf("Decrypted (mutated, should not match):\n");
                show_hexstr(str2, sizeof(str2));
                printf("\n");
                
                printf("Bounds: %x %x %x\n", bound, bound2, bound3);
            }
         }
     }
    return 0;
}

/* EOF */




