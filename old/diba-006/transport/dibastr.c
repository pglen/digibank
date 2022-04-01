
/* =====[ dibastr.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  jul.22.2017     Peter Glen      Sexp helpers

   ======================================================================= */

#include "dibastr.h"

// -----------------------------------------------------------------------
// Unified strings for key files, definitons

const char *pub_start  = "-----BEGIN DIGIBANK RSA PUBLIC KEY-----";
const char *pub_end    = "-----END DIGIBANK RSA PUBLIC KEY-----";

const char *comp_start = "-----BEGIN DIGIBANK RSA COMPOSITE KEY-----";
const char *comp_end   = "-----END DIGIBANK RSA COMPOSITE KEY-----";

const char *cyph_start = "-----BEGIN DIGIBANK RSA CIPHER-----";
const char *cyph_end   = "-----END DIGIBANK RSA CIPHER-----";

const char *mod_start  = "-----BEGIN DIGIBANK PUBLIC MODULUS-----";
const char *mod_end    = "-----END DIGIBANK PUBLIC MODULUS-----";
    
const char *exp_start  = "-----BEGIN DIGIBANK PUBLIC EXPONENT-----";
const char *exp_end    = "-----END DIGIBANK PUBLIC EXPONENT-----";
    
const char *keypass = "12345678";

