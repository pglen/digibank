
/* =====[ dibautils.h ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.25.2017     Peter Glen      Initial version.

   ======================================================================= */

#include "gcrypt.h"

typedef struct _build_next_struct
{
    char *next_calc;
    char *next_hash;
    char *next_pad;
    char *next_id;
    char *next_file;
    char *next_workhash;

} build_next_struct;

#define INIT_NEXT_STRUCT(st)           \
        (st)->next_calc = (char*)nonestr;        \
        (st)->next_hash = (char*)nonestr;        \
        (st)->next_pad = (char*)nonestr;         \
        (st)->next_id = (char*)nonestr;          \
        (st)->next_file = (char*)nonestr;        \
        (st)->next_workhash = (char*)nonestr;    \

void    rand_buff(char *str, int len);
void    rand_str(char *str, int len);
void    rand_asci_buff(char *str, int len);
void    show_str(const char* str, int len);
void    show_str_lines(const char* str, int len);
int     str_fromhex(char *str, int len, char *str2, int *olen);
void    genrev(char *str, int len);
char    *diba_alloc(int size);
int     read_sexp_from_file(const char *fname, gcry_sexp_t *sexp, char **err_str);
int     write_sexp_to_file(const char *fname, gcry_sexp_t *sexp, char **err_str);

int     build_next(gcry_sexp_t *chain_next, build_next_struct *bns);













