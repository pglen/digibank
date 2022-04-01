
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>

#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"

int keysize = 4096;

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rsa-keypair.sp>\n", argv[0]);
        xerr("Invalid arguments.");
    }

    gcrypt_init();

    char* fname = argv[1];
    if(access(fname, F_OK) >= 0)
        {
        //xerr("File already exists, use different name or delete the file.");
        }
        
    //FILE* lockf = fopen(fname, "wb");
    //if (!lockf) {
    //    xerr("fopen() failed");                                                              
    //}

    /* Generate a new RSA key pair. */
    printf("RSA key generation can take a few minutes. Your computer "
           "needs to gather random entropy.\n\nPlease wait ... \n\n");

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;

    char key_str[56]; 
    sprintf(key_str, "(genkey (rsa (nbits 4:%d)))", keysize);
    err = gcry_sexp_build(&rsa_parms, NULL, key_str);
    if (err) {
        xerr("gcrypt: failed to create rsa params");
    }

    //printf("RSA key generation in progress ... please wait ...");
    
    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        xerr("gcrypt: failed to create rsa key pair");
    }
    printf("\n");
    
    //gcry_sexp_dump(rsa_keypair);
    int ss = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *ppp = (char*)malloc(ss+1);
    gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, ppp, ss);
    printf("%s\n", ppp);
    
    printf("\nRSA key generation complete!\nPlease enter a password to lock \n"
           "your key pair. This password must be retained for later use.\n\n");

    /* Grab a key pair password and create an encryption context with it. */
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd);

    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(keysize);
    void* rsa_buf = calloc(1, rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);

    err = gcry_cipher_encrypt(aes_hd, (unsigned char*) rsa_buf, 
                              rsa_len, NULL, 0);
    if (err) {
        xerr("gcrypt: could not encrypt with AES");
    }

    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr("fopen() failed");                                                              
    }
    
    /* Write the encrypted key pair to disk. */
    if (fwrite(rsa_buf, rsa_len, 1, lockf) != 1) {
        perror("fwrite");
        xerr("fwrite() failed");
    }
    
    fclose(lockf);

    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    gcry_cipher_close(aes_hd);
    free(rsa_buf);
 
    return 0;
}




