
/* =====[ dibautils.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.22.2017     Peter Glen      Initial version.

   ======================================================================= */


#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "diba.h"
#include "dibautils.h"
#include "bluepoint2.h"

// Generate random string in place. Favour lower case letters.

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
    char *str2 = bluepoint2_dump((char*)str, len);
    printf("%s", str2);
}   

void show_hexstr(const char* str, int len)

{
    char *str2 = bluepoint2_dumphex(str, len);
    printf("%s\n", str2);
}   

/*
 * Read command line switches, set globals.
 *
 * In:      Arguments, procession options, place for error str
 * Out:     Args parsed
 * Return:  Last index processed
 # Pointer to an error message or NULL
 *
 */

int     parse_commad_line(char **argv, opts *popts_data, char **err_str)

{
    int     got, nn, processed = 0, err = 0;
    char    *ret_val = NULL;

    *err_str = NULL;
    
    for (nn = 1; argv[nn] != NULL; nn++)
        {
        if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            int idx = 0;
            char cmd = tolower(argv[nn][1]);
            if(cmd == '?' || cmd == 'h')
                {
                *err_str = "Help requested.";
                return nn;
                }
            got = 0;
            while(TRUE)
                {
                if(popts_data[idx].opt == 0)
                    {
                    if(got == 0)
                        err++;
                    else
                        processed++;                        
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
                            *err_str = "Invalid value on option\n";
                            return nn;
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
        *err_str = "Invalid option on command line\n";    
        
    return(processed);
}

//////////////////////////////////////////////////////////////
// Reverse string in place

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


