
/* =====[ ascrypt.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.

   ======================================================================= */

#include "gcrypt.h"

#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

char *baselim(const char *mem, int len);

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pub_file>\n", "ascrypt");
        xerr("Invalid arguments.");
    }

    //zverbose(1);
    gcrypt_init();
    gcry_error_t err;

    char* fname = argv[1];

    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr("fopen() failed");
    }

    /* Grab the public key size */
    
    unsigned int rsa_len = getfsize(lockf);
    //printf("Key file size %d\n", rsa_len);
    
    zline(__LINE__);
    void* rsa_buf = zalloc(rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }

    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr("fread() failed");
    }
    //printf("%s\n", rsa_buf);
    
    gcry_sexp_t pubkey;
    err = gcry_sexp_new(&pubkey, rsa_buf, rsa_len, 1);
    
    if (err) {
        xerr("gcrypt: failed to read public key");
    }
    print_sexp(pubkey);
    
    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    const unsigned char* s = (const unsigned char*)
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";

    //dump_mem(s, strlen(s));

    #if 0
    int outlen = base64_calc_encodelen(strlen(s));
    zline(__LINE__);
    char *mem = zalloc(outlen);
    base64_encode(s, strlen(s), mem, &outlen);
    zcheck(mem, __LINE__);
    printf("base64\n%s\n", mem);
    
    int declen = base64_calc_decodelen(outlen);
    char *dmem = zalloc(declen);
    base64_decode(mem, outlen, dmem, &declen);
    printf("dec base64\n%s\n", dmem);
    dump_mem(dmem, strlen(dmem));
    zcheck(dmem, __LINE__);
    zfree(mem);
    #endif
    
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, s,
                        strlen((const char*) s), NULL);

    if (err) {
        xerr("failed to create a mpi from the message");
    }

    err = gcry_sexp_build(&data, NULL,
                           "(data (flags raw) (value %m))", msg);
    if (err) {
        xerr("failed to create a sexp from the message");
    }

    /* Encrypt the message. */
    gcry_sexp_t ciph;
    err = gcry_pk_encrypt(&ciph, data, pubkey);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

    gcry_mpi_t msg2;
    gcry_sexp_t data2;
    char *ss = strdup(s);
    ss[0] = 'J';
    err = gcry_mpi_scan(&msg2, GCRYMPI_FMT_USG, ss,
                        strlen((const char*) ss), NULL);

    printf("\n" "Cypher:\n");
    gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
    //print_sexp(ddd);
    
    unsigned int plen = 0;
    const char *ptr = gcry_sexp_nth_data(ddd, 1, &plen);
    //dump_mem(ptr, plen);
    
    char *mem3 = baselim(ptr, plen);
    printf("%s\n", "-----BEGIN RSA PUBLIC KEY-----");
    printf("%s\n", mem3);
    printf("%s\n", "-----END RSA PUBLIC KEY-----");
    
    zfree(mem3);
    
    /* Release contexts. */
    gcry_mpi_release(msg);
    
    gcry_sexp_release(pubkey);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);
    
    zline(__LINE__);
    zfree(rsa_buf);
    
    fclose(lockf);

    zleak();
    return 0;
}



