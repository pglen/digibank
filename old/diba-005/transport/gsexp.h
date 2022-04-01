
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug03.2017     Peter Glen      Initial version.

   ======================================================================= */

// Sexp helpers
char    *sprint_sexp(gcry_sexp_t sexp, int *len, int format);
void    print_sexp(gcry_sexp_t rsa_keypair);
int     decode_sexp(gcry_sexp_t list, const char *findstr);
char    *get_sexp_buff(gcry_sexp_t sexp, int *plen);
char    *sexp_nth_data(gcry_sexp_t  element, int num, int *plen);
char    *hash_sexp(gcry_sexp_t pubk, int *olen);
int     list_sexp(gcry_sexp_t list);

// General memory helpers
void    dump_mem(const char *ptr, int len);
int     print_mem(char *mem, int len);
char    *dohex(char *mem, int len, int *olen);
char    *dounhex(char *mem, int len, int *olen);









