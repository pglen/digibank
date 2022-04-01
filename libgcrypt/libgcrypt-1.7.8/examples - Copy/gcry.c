
/* =====[ gcry.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.17.2017     Peter Glen      Added dump mem

   ======================================================================= */

#include <stdlib.h>

#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"

void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);                                
}

void printerr(int err, char *str)

{
    fprintf (stderr, "%s\n", str);

    fprintf (stderr, "Failure: &#37;s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
    fprintf (stdout, "Failure: %s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
}       


void gcrypt_init()

{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        xerr("gcrypt: library version mismatch");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        xerr("gcrypt: failed initialization");
    }
}

size_t get_keypair_size(int nbits)
{
    size_t aes_blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);

    // format overhead * {pub,priv}key (2 * bits)
    size_t keypair_nbits = 4 * (2 * nbits);

    size_t rem = keypair_nbits % aes_blklen;
    return (keypair_nbits + rem) / 8;
}

void get_aes_ctx(gcry_cipher_hd_t* aes_hd)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];

    char ppp[MAXPASSLEN + 1];

    char* passwd = getpass("Keypair Password: ", ppp, MAXPASSLEN);
    size_t pass_len = passwd ? strlen(passwd) : 0;
    if (pass_len == 0) {
        xerr("getpass: not a valid password");
    }

    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_AES128, 
                               GCRY_CIPHER_MODE_CFB, 0);
    if (err) {
        xerr("gcrypt: failed to create aes handle");
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, (void*) &passwd_hash, 
                        (const void*) passwd, pass_len);

    err = gcry_cipher_setkey(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr("gcrypt: could not set cipher key");
    }

    err = gcry_cipher_setiv(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr("gcrypt: could not set cipher initialization vector");
    }
}

//////////////////////////////////////////////////////////////////////////

void print_sexp(gcry_sexp_t rsa_keypair)

{
    int ss = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *ppp = (char*)malloc(ss+1);
    if(ppp == NULL)
        return;
    gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, ppp, ss);
    printf("%s\n", ppp);
    free(ppp);
}    

void dump_mem(const char *ptr, int len)
{
    int loop, cut = 16, base = 0;
    
    if (ptr == NULL) 
        {
        printf("NULL\n");
        return;
        }
        
    printf("Begin: %p (len=%d)\n", ptr, len);
    while(1==1)
        {
        printf(" ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                printf("%.02x", ptr[base + loop] & 0xff);
                if(loop < 15)
                    printf("-");
                }
            else
                printf("   ");
            }
        printf("   ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                unsigned char chh = ptr[base + loop] & 0xff;
                if(chh < 128 && chh >= 32 )
                    printf("%c", chh);
                else
                    printf(".");
                }
            else
                printf(" ");
            }
        printf("\n");
        base += 16;
        if(base >= len)
            break;
        }
    printf("End\n");
}    

