
/* =====[ dibagen.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.
      0.10  Jul.04.2017     Peter Glen      Adapted to high round processing

   ======================================================================= */

// Dibapow proof of work. It takes about a millon calculations for the hash 
// to go below 0x2000. On avarage 10 million trues lead to 8 - 10 hits.

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
                    "-n[num]  - number of entries to generate default to 1, range(1-16M)",
                    's',    &skip,  0, 0xffff, NULL, 
                    "-s[num]  - number of entries to skip default to 0, range(1-16M)",
                    'm',    &skip,  0, 0xffff, NULL, 
                    "-m[num]  - Mode of generation, default to 0, range(0-255)",
                    'v',    NULL,  0, 0, &verbose, 
                    "-v       - Verbosity on",
                     0,      NULL,      0, 0,  NULL, NULL,
                    };
                 
char org_str[]  = "Hello World ";
char test_str[] = "            ";
char test_pass[] = "1234";

int     usage(void);

///////////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    //printf("nn=%d\n", nn);
    if (err_str)
        {
        printf(err_str);
        usage(); exit(2);
        }
    
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaPOW written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    UINT  loop;
    int pass_len = strlen(test_pass);
    int test_len = strlen(test_str);
    int org_len = strlen(org_str);
    int sum_len = org_len + test_len;

    char *sum_str = malloc(sum_len + 2); 
    
    //ASSERT(sum_str);
    
    memcpy(sum_str, org_str, org_len);
            
    //rand_str(test_str, test_len);
    //printf("%s\n", test_str);
    //exit(0);
    
    srand(time(NULL));
      
    //bluepoint2_set_verbose(TRUE);
    //bluepoint2_set_looping(3);
    
    UINT looping = 100000;
    for(loop = 0; loop < looping; loop++)
        {
        rand_str(test_str, test_len);
        memcpy(sum_str + org_len, test_str, test_len);
    
        //ulonglong   hash = bluepoint2_crypthash64(sum_str, sum_len, test_pass, pass_len);
        ulong   hash = bluepoint2_crypthash64(sum_str, sum_len, test_pass, pass_len);
        
        uint tresh = 0x80000;
        if (hash < tresh || loop % (looping / 10) == 0)
                {
                show_str((const char *)sum_str, sum_len);
                //printf("%08d - %I64x ", loop, hash);
                printf("%08d - %8x ", loop, hash);
                if (hash < tresh)
                    printf(" Match");
                printf("\n");
                }
        }
    
    printf("\n");
    
    //printf("\n");
    return 0;
}

int     usage(void)

{
    int  idx = 0, ret_val = 0;
    
    printf("\
\n\
Usage: dibapow [options]\n\
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



