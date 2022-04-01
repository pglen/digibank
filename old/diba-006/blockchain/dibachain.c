
/* =====[ dibachain.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.
      0.10  oct.23.2017     Peter Glen      Dump and last.

   ======================================================================= */

// Dibachain is the block chain as files

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diba.h"

#include "bluepoint3.h"
#include "dibautils.h"
#include "cmdline.h"
#include "dibastr.h"
#include "zstr.h"
#include "zmalloc.h"
#include "gsexp.h"

//#define TEST

static int        show_chain(int dump);

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;

static int  add = 0;
static int  show = 0;
static int  dump = 0;
static int  check = FALSE;
static int  batch = TRUE;
static int  verbose = FALSE;
static int  test = FALSE;
static int  last = FALSE;

opts opts_data[] = {
                    'd',   "--dump",  &dump,  NULL, 0, 0xffff, NULL, 
                    "-d             --dump        - dump the chain to screen",
                    'l',   "--last",  NULL,  NULL, 0, 0xffff, &last, 
                    "-l             --last        - show last in chain",
                    's',   "--show",  NULL,  NULL, 0, 0xffff, &show, 
                    "-s             --show        - show the chain",
                    'c',   "--check",  NULL,  NULL, 0, 0xffff, &check, 
                    "-c             --check       - check chain integrity",
                    'v',     "--verbose", NULL, NULL,  0, 0,  &verbose, 
                    "-v             --verbose     - Verbosity on",
                     0,      NULL, NULL, NULL,      0, 0,  NULL, NULL,
                    };

char test_pass[] = "1234";

char progname[] = "dibachain [options]";
char descr[] =  "Show / dump / check diba chain";

///////////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    //printf("nn=%d\n", nn);
    if (err_str)
        {
        printf(err_str);
        usage(progname, descr, opts_data); exit(2);
        }

    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaChain written by Peter Glen.                             \n\
---------------------------------------------------------------------------\n\
\n\
");
    
    if(show)
        {
        printf("Showing chain items:\n\n");
        show_chain(show + verbose);
        }
    else if(last)
        {
        //printf("Last chain item\n");
        show_chain(0);
        }
    else if(dump)
        {
        printf("Dumping chain items\n");
        //show_chain(1);
        }
    else if(check)
        {
        printf("Checking chain items\n");
        }
    else
        {
        printf("Must use one of the commands: 's' 'c' 'd'\n");
        usage(progname, descr, opts_data); exit(2);
        }
    
    printf("\n");
    zleak();
    
    return 0;
}

int     show_one(char **fname, int dump)

{
    gcry_error_t err = 0;
    int ret = 0;
    
    if(dump > 0)
        printf("File '%s' ", *fname);
    
    if(access(*fname, F_OK) < 0)
        return ret;
       
    char *err_str;    
    gcry_sexp_t showsexp;
    read_sexp_from_file(*fname, &showsexp, &err_str);
    
    //print_sexp(showsexp);
        
    // See if it has a next already
    gcry_sexp_t  nid = gcry_sexp_find_token(showsexp, "Next File", 0);
    if (!nid)
        {
        printf("Failed to find 'Next File' in back sexp. %s\n", gcry_strerror (err));
        return 0;
        }
        
    int nlen;
    char  *nnn  = sexp_nth_data(nid, 1, &nlen);
    if (!nnn)
        {
        printf("Failed to read 'Next File' member in back sexp. %s\n", gcry_strerror (err));
        return 0;
        }
    // Has next file?
    if(strcmp(nnn, nonestr) != 0)
        {                     
        ret = 1;
        zfree(*fname);
        *fname = nnn;
        }
    else
        {
        //zfree(*fname);
        }
        
    if(dump > 0)
        {    
        gcry_sexp_t  bl = gcry_sexp_find_token(showsexp, "ID", 0);
        if (!bl)
            printf("Failed to find ID in back sexp.\n");
    
        int olen;
        zline2(__LINE__, __FILE__);
        char *ddd2 =  sexp_nth_data(bl, 1, &olen);
        printf("ID '%s'   ", ddd2);
        zfree(ddd2);
        gcry_sexp_t  pl = gcry_sexp_find_token(showsexp, "Payload Data", 0);
        if (!pl)
            {
            printf("Failed to find payload in back sexp.\n");
            return ret;
            }
        int plen;
        char *sss = "Saved in file: ";
        zline2(__LINE__, __FILE__);
        char *ddd3 =  sexp_nth_data(pl, 1, &plen);
        if(strncmp(ddd3, sss, strlen(sss)) == 0)
            {
            char *end, *start = strchr(ddd3, '\'');
            if(start)
                {
                start++;
                end = strrchr(ddd3 , '\'');
                if(end)
                    {
                    *end = '\0';
                    //printf("Payload file '%s'\n", start);
                    struct stat sss;
                    if(stat(start, &sss) < 0)  
                        {
                        printf("Cannot stat payload file '%s'\n", start);
                        }
                    else        
                        {
                        printf("Payload size: %d\n", sss.st_size);
                        }
                    }
                }
            }
        else
            {
            printf("Payload size: %d\n", plen);
            }
        zfree(ddd3);
       }
    if(dump == 2)
        {
        char *err_str; int olen;
        char *ddd4 = sexp_get_val(showsexp, "Description", &olen, &err_str);
        if(err_str)
            {
            printf("%s", err_str);
            }
        else
            {
            printf("Description: '%s'\n", ddd4);  
            }
        zfree(ddd4);
        
        char *ddd5 = sexp_get_val(showsexp, "Creation Date", &olen, &err_str);
        if(err_str)
            {
            printf("%s", err_str);
            }
        else
            {
            printf("Creation Date: '%s'\n", ddd5);  
            }
        zfree(ddd5);
        
        printf("\n");
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
//

int        show_chain(int dump)

{
    char *fname = zstrmcat(MAX_PATH, nulldir, nullfname, nullext, NULL); 
    while(TRUE)
        {
        if(!show_one(&fname, dump))
            break;
        }
    if(dump == 0)
        {
        printf("%s\n", fname);
        }
    zfree(fname);
    return 0;
}

/* EOF */
