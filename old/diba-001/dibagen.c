
/* =====[ dibagen.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.

   ======================================================================= */

// DibaGen test script

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

#define TEST

static  void    genrev(char *str, int len);
static void     showstr(char *str, int len);

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static char batch = TRUE;
static char verbose = FALSE;
static char test = FALSE;

char pass[] = "1234";

int    main(int argc, char *argv[])

{
    parse_commad_line(argv);

    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaGen written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    UINT bound = 0;
    UCHAR str[BSIZE]; 
    UINT bound2 = 0;
    UCHAR str2[BSIZE]; 
    UINT bound3 = 0;
    
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
            #ifdef TEST
            if (test) {
                printf("Original:\n");
                showstr(str, sizeof(str));
            }
            #endif
            
            memcpy(str2, str, sizeof(str2));
            bluepoint2_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
            showstr(str2, sizeof(str2));
    
            #ifdef TEST
            // Verify
            if (test) {
                bluepoint2_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
                showstr(str2, sizeof(str2));
                printf("\n");
                
                 if (memcmp(str, str2, sizeof(str2)))
                    {
                    printf("Bad decription!\n\n");
                    }        
                   
                // Verify mutation
                printf("Mutate:\n");
                memcpy(str2, str, sizeof(str2));
                showstr(str2, sizeof(str2));
        
                bluepoint2_encrypt(str2, sizeof(str2),  pass, sizeof(pass));
                //showstr(str2, sizeof(str2));
                str2[2] = str2[2] + 1;
                showstr(str2, sizeof(str2));
                bluepoint2_decrypt(str2, sizeof(str2),  pass, sizeof(pass));
                showstr(str2, sizeof(str2));
                printf("\n");
                
                printf("Bounds: %d %d %d\n", bound, bound2, bound3);
            }
            #endif
         }
     }
    //printf("\n");
    return 0;
}

//////////////////////////////////////////////////////////////

void    showstr(char *str, int len)

{
    //char *str2 = bluepoint2_dumphex(str, len);
    char *str2 = bluepoint2_dump(str, len);
    printf("%s\n", str2);
}   
    
//////////////////////////////////////////////////////////////////////////

void    genrev(char *str, int len)

{
    int loop, bb;
    
    if (len <= 10)
        {
        printf("Must have more than 10 bytes\n");
        return;
        }
    
    // Init beginning
    //for (bb = 0; bb < 8; bb++)
    //    str[bb] = '\0';
        
    // Count up
    for(loop = len-(ASIZE+1); loop >= ASIZE; loop--)
        {
        UCHAR cc = str[loop];
        if(cc == 0xff)
            {
            str[loop] = 0;
            }
        else
           {
           str[loop] = ++cc;
           break;
           }
        }
}


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
                            if(mode > 255 || mode < 0)
                                {
                                fprintf(stderr, "Mode out of range\n");
                                usage(); exit(1);
                                }
                            argv[nn][0] = '\0'; break;

                case 'b':   batch = TRUE;
                            argv[nn][0] = '\0'; break;

                case 't':   test = TRUE;
                            argv[nn][0] = '\0'; break;

                case 'v':   verbose = TRUE;
                            argv[nn][0] = '\0'; break;
                            
                case 'h':   
                case '?':   usage();  exit(0); break;
                }
            }
        }
    return(ret_val);
}

int     usage(void)

{
    int  ret_val = 0;
    printf("\
\n\
Usage: dibagen [options]\n\
\n\
Options can be:     -n[num]  - number of entries to generate default=1 range (1-16M)\n\
                    -m[num]  - mode default=0 range (0-255)\n\
                    -s[num]  - skip default=0 range (0-16M)\n\
                    -b       - batch mode on\n\
                    -v       - verbose on\n\
                    -t       - test on\n\
                    -?       - displays this help\n\
                    -h       - displays this help\n\
\n\
");
    return(ret_val);
}

/* EOF */



























