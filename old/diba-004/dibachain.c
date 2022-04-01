
/* =====[ dibachain.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.

   ======================================================================= */

// Dibachain is the block chain as files

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

//#include <curses.h>

#include "bluepoint2.h"
#include "diba.h"
#include "dibautils.h"

#define TEST

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;

static int  add = 0;
static int  dump = 0;

static int mode = 0;
static int batch = TRUE;
static int verbose = FALSE;
static int test = FALSE;


opts opts_data[] = {
                    'n',    &entries,  0, 0xffff, NULL, 
                    "-n[num]  - number of entries to generate default to 1, range(1-16M)",
                    's',    &skip,  0, 0xffff, NULL, 
                    "-s[num]  - number of entries to skip default to 0, range(1-16M)",
                    'm',    &skip,  0, 0xffff, NULL, 
                    "-m[num]  - Mode of generation, default to 0, range(0-255)",
                    'v',     NULL,  0, 0, &verbose, 
                    "-v       - Verbosity on",
                     0,      NULL,      0, 0,  NULL, NULL,
                    };


char org_str[]  = "Hello World ";
char test_str[] = "            ";
char test_pass[] = "1234";

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
              DibaChain written by Peter Glen.                             \n\
---------------------------------------------------------------------------\n\
\n\
");
    
    if(add)
        {
        printf("Adding item\n");
        }
    else if(dump)
        {
        printf("Dumping chain items\n");
        }
    else
        {
        printf("Must use one of the commands 'a' 'd'\n");
        usage(); exit(1);
        }
    
    printf("\n");
    
    return 0;
}

#if 0

/*
 * Read command line switches, set globals.
 *
 * Return:  TRUE if command line is OK.
 *
 */

int     parse_commad_line(char **argv)

{
    int     nn, ret_val = FALSE;

    for (nn = 1; argv[nn] != NULL; nn++)
        {
        if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            switch(tolower(argv[nn][1]))
                {
                case 'n':   entries = atoi(&argv[nn][2]);
                            //printf("entries %d\n", entries);
                            if(entries <= 0 || entries > 0xffffff)
                                {
                                fprintf(stderr, "Iteration number out of range.\n");
                                usage(); exit(1);
                                }
                            argv[nn][0] = '\0'; break;

                case 's':   skip = atoi(&argv[nn][2]);
                            //printf("skip %d\n", skip);
                            if(skip <= 0 || skip >= entries)
                                {
                                fprintf(stderr, "Skip number out of range.\n");
                                usage(); exit(1);
                                }
                            argv[nn][0] = '\0'; break;

                case 'm':   mode = atoi(&argv[nn][2]);
                            //printf("mode %d\n", mode);
                            if(mode > 9 )
                                {
                                fprintf(stderr, "Mode out of range\n");
                                usage(); exit(1);
                                }
                            argv[nn][0] = '\0'; break;

                case 'a':   add = TRUE;
                            argv[nn][0] = '\0'; break;

                case 'd':   dump = TRUE;
                            argv[nn][0] = '\0'; break;

                case 't':   test = TRUE;
                            argv[nn][0] = '\0'; break;

                case 'v':   verbose = TRUE;
                            argv[nn][0] = '\0'; break;
                            
               case 'h':   usage();  exit(0); break;
                case '?':   usage();  exit(0); break;
                }
            }
        }
    return(ret_val);
}

#endif

int     usage(void)

{
    int  ret_val = 0;
    printf("\
\n\
Usage: dibapow [options]\n\
\n\
Options can be:     -n[num]  - number of entries to generate def[1] range(1-16M)\n\
                    -m[num]  - mode def[0][ range(0-9)\n\
                    -s[num]  - skip def[0][ range(0-n)\n\
                    -b       - batch mode on\n\
                    -v       - verbose on\n\
                    -a       - add new item \n\
                    -d       - dump items \n\
                    -t       - test on\n\
                    -?       - displays this help\n\
                    -h       - displays this help\n\
\n\
");
    return(ret_val);
}

/* EOF */

