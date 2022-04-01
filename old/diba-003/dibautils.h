
/* =====[ dibautils.h ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.25.2017     Peter Glen      Initial version.

   ======================================================================= */


typedef struct _opts
{
    char    opt;
    int     *val;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts;


void rand_str(char *str, int len);
void show_str(const char* str, int len);
void show_hexstr(const char* str, int len);

void genrev(char *str, int len);

//
// Sample option data:
// opts opts_data[] = {
//    'n',    &entries,  0, 0xffff, NULL, 
//    "-n[num]  - number of entries to generate default to 1, range(1-16M)",
//    'v',    NULL,  0, 0, &verbose, 
//    "-v       - Verbosity on",
//     0,      NULL,      0, 0,  NULL, NULL,
//    };
//
//

int     parse_commad_line(char **argv, opts *popts_data, char **err_str);




