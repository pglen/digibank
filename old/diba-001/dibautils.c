
/* =====[ dibautils.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.22.2017     Peter Glen      Initial version.

   ======================================================================= */


#include <stddef.h>

#include "diba.h"
#include "bluepoint2.h"

void rand_str(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len; loop++)
        {
        //str[loop] = rand() % 255;
        
        // Favour lower case letters
        int ttt = rand() % 4;
        if (ttt == 0)
            str[loop] = (rand() % 10) + '0';
        else if (ttt == 1)
            str[loop] = (rand() % 26) + 'A';
        else
            str[loop] = (rand() % 26) + 'a';
        }
}

void show_str(const char* str, int len)
{
    //char *str2 = bluepoint2_dumphex(str, len);
    char *str2 = bluepoint2_dump((char*)str, len);
    printf("%s '%s' ", str2, str);
}   

typedef struct _opts
{
    char    opt;
    int     *val;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts;

/*
 * Read command line switches, set globals.
 *
 * Return:  TRUE if command line is OK.
 *
 */

char    *parse_commad_line(char **argv, opts *popts_data)

{
    int     got, idx, nn, err = 0;
    char    *ret_val = NULL;

    for (nn = 1; argv[nn] != NULL; nn++)
        {
        if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            idx = 0;
            char cmd = tolower(argv[nn][1]);
            if(cmd == '?' || cmd == 'h')
                return "Help requested.";
                
            while(TRUE)
                {
                got = 0;
                if(popts_data[idx].opt == 0)
                    {
                    if(got == 0)
                        err++;
                    break;
                    }   
                if(popts_data[idx].opt == cmd)
                    {
                    got++;
                    //printf("Got command %c\n", cmd);
                    if(popts_data[idx].val != NULL)
                        {
                        int val = atoi(&argv[nn][2]);
                        if(popts_data[idx].minval > val ||
                                popts_data[idx].maxval < val) 
                            {
                            return "Invalid value on option\n";
                            }
                        *popts_data[idx].val =  val;
                        } 
                    else if(popts_data[idx].flag != NULL)
                        {
                        *popts_data[idx].flag = TRUE;
                        }
                    }
                 idx++;
                }
            }
        }
    if (err)
        return "Invalid option on command line\n";    
    else
        return(NULL);
}

