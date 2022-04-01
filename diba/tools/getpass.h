                                               
/* =====[ getpass.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.
      0.00  jul.30.2017     Peter Glen      Added getpass2

   ======================================================================= */

#define ALLOW_TRIES 3
#define MINPASSLEN  4

#define CRTL_C     '\3'
#define CRTL_D     '\4'

typedef struct _getpassx

{
    char *prompt;
    char *prompt2;
    char *pass;
    int  maxlen;
    int  weak; 
    int  nodouble;
    int  minlen;
    int  strength;
    int  debug;

} getpassx;

#define ZERO_GETP_STRUCT(gp) memset(gp, 0, sizeof(getpassx));

int getdibapass(const char *prompt, char *ppp, int maxlen);

int getpass2(getpassx *passx);

// EOF






