
/* =====[ DigiBank.c ]=========================================================

   Description:     Feasability study for digibank

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.

   ======================================================================= */

// DigiBank test script

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
//#include <curses.h>

#define DEF_DUMPHEX
#include "bluepoint2.h"

/* -------- Defines: ----------------------------------------------------- */

#define TRUE 1
#define FALSE 0

#define TAB 9

static  void    genstr(char *str, int len);
static  void    showstr(char *str, int len);

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;
static uint gl_timeout   =  4 * CLOCKS_PER_SEC;
static char batch = FALSE;
static char *pass = "digibank";

int    main(int argc, char *argv[])

{
    //parse_commad_line(argv);

    if(!batch)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DigiBank written by Peter Glen.                              \n\
---------------------------------------------------------------------------\n\
\n\
");

    //if(!argv[1] || !argv[2] || *argv[1] == '?')
    //    {
    //    usage();
    //    }
                       
    char str[24]; 
    unsigned int aa = 0;
    
    for(aa = 0; aa < 0xffffffff; aa++)
        {
        if(aa % 2000 == 0)
            {
            printf("\r%d ", aa); 
            }
            
        genstr(str, sizeof(str));
        showstr(str, sizeof(str));
        
        bluepoint2_encrypt(str, sizeof(str),  pass, sizeof(pass));
        showstr(str, sizeof(str));

        // Verify
        bluepoint2_decrypt(str, sizeof(str),  pass, sizeof(pass));
        showstr(str, sizeof(str));
        printf("\n");
        
        if(str[0] == '\0' && str[1] == '\0' && str[2] == '\0')
            {
            printf("Null Lead\n");
            showstr(str, sizeof(str));
            bluepoint2_decrypt(str, sizeof(str),  pass, sizeof(pass));
            showstr(str, sizeof(str));
            printf("\n");
            }
        }
                        
    printf("\n");
    return 0;
}

//////////////////////////////////////////////////////////////

void    showstr(char *str, int len)

{
    char *str2 = bluepoint2_dumphex(str, len);
    printf("%s\n", str2);
}   
    
    
//////////////////////////////////////////////////////////////////////////

void    genstr(char *str, int len)

{
    int aa = 0;
    
    for(aa = 0; aa < len; aa++)
        {
        str[aa] = rand();
        }
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
    int     nn, ret_val = FALSE, timeout = 0;

    for (nn = 1; argv[nn] != NULL; nn++)
        {
        if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            switch(toupper(argv[nn][1]))
                {
                case 'T':   timeout = atoi(&argv[nn][2]);
                            if(timeout)
                                gl_timeout = timeout * CLOCKS_PER_SEC;
                            argv[nn][0] = '\0'; break;

                case 'B':   batch = TRUE;
                            argv[nn][0] = '\0'; break;

                case '?':   usage(); break;
                }
            }
        }
    return(ret_val);
}

#endif

int     usage(void)

{
    int  ret_val;

#if 0
        printf("\\
\n\\
Asking user to whether to execute a program. If no answer is given,\n\\
timeout will execute default. Great for net or win startup.\n\\
\n\\
Usage: ASKEXEC \"Prompt string\" ExecOnYes [ExecOnNo] [options]\n\\
\n\\
Where:              \"Prompt string\" - string to display to the user\n\\
                    ExecOnYes       - execute on answering yes \n\\
                    ExecOnNo        - execute on answering no\n\
\n\
Options can be:     -t[xx]  - timeout [time in seconds follow]\n\
                    -d[x]   - default answer (Y, N, A) default: Y\n\
                    -d[x]   - default answer (Y, N, A) default: Y\n\
                    -b      - supress banner (batch mode)\n\
                    -?      - displays this help\n\
\n\
Examples:\n\
\n\
ASKEXEC \"Load net ?\" net\n\
ASKEXEC \"Start windows ?\" win \n\
ASKEXEC \"Start word processing ?\" \"wprocess text.doc\"\n\
");
#endif

    exit(0);


    return(ret_val);
}

/* EOF */


















