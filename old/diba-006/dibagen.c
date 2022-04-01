
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

#include "bluepoint2.h"
#include "diba.h"
#include "dibautils.h"

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  batch = TRUE;
static int  verbose = FALSE;
static int  test = FALSE;

opts opts_data[] = {
                    'n',    &entries,  0, 0xffff, NULL, 
                    "-n[num]  - number of entries to generate defaults to 1, range(1-16M)",
                    's',    &skip,  0, 0xffff, NULL, 
                    "-s[num]  - number of entries to skip defaults to 0, range(1-16M)",
                    'm',    &skip,  0, 0xffff, NULL, 
                    "-m[num]  - Mode of generation, defaults to 0, range(0-255)",
                    'v',    NULL,  0, 0, &verbose, 
                    "-v       - Verbosity on",
                    't',    NULL,  0, 0, &test, 
                    "-t       - test on",
                     0,      NULL,      0, 0,  NULL, NULL,
                    };

char pass[] = "1234";

int     usage(void);

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
        usage(); exit(2);
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
    
    //bluepoint2_set_verbose(TRUE);
    //bluepoint2_set_rounds(3);
    
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
            bluepoint2_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
            if (test)
                printf("Encrypted:\n");
            show_hexstr(str2, sizeof(str2));
            printf("\n");
    
            // Verify
            if (test) {
                bluepoint2_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
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
        
                bluepoint2_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
                str2[2] = str2[2] + 1;
                show_hexstr(str2, sizeof(str2));
                bluepoint2_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
                printf("Decrypted (mutated, should not match):\n");
                show_hexstr(str2, sizeof(str2));
                printf("\n");
                
                printf("Bounds: %x %x %x\n", bound, bound2, bound3);
            }
         }
     }
    return 0;
}

int     usage(void)

{
    int  idx = 0, ret_val = 0;
    
    printf("\
\n\
Usage: dibagen [options]\n\
\n\
Options can be:     \n\
");

   while(TRUE)
        {
        if(opts_data[idx].opt == 0)
            break;
            
        printf("               %s\n", opts_data[idx].help);
        idx++;
        }
    printf(    "               -?       - displays this help\n");
    printf(    "               -h       - displays this help\n");
    
    return(ret_val);
}

/* EOF */


