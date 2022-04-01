
/* =====[ main.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include "gcrypt.h"

#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rsa-keypair.sp>\n", argv[0]);
        xerr("Invalid arguments.");
    }

    gcrypt_init();
    gcry_error_t err;

    char* fname = argv[1];

    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr("fopen() failed");
    }

    /* Grab a key pair password and create an AES context with it. */
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd);

    /* Read and decrypt the key pair from disk. */
    size_t rsa_len = get_keypair_size(4096);
    void* rsa_buf = calloc(1, rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }

    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr("fread() failed");
    }

    err = gcry_cipher_decrypt(aes_hd, (unsigned char*) rsa_buf,
                              rsa_len, NULL, 0);
    if (err) {
        xerr("gcrypt: failed to decrypt key pair");
    }

    /* Load the key pair components into sexps. */
    gcry_sexp_t rsa_keypair;
    err = gcry_sexp_new(&rsa_keypair, rsa_buf, rsa_len, 0);
    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    const unsigned char* s = (const unsigned char*)
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";

    //dump_mem(s, strlen(s));

    int outlen = base64_calc_encodelen(strlen(s));
    char *mem = zalloc(outlen);
    //memset(mem, 'a', outlen);
    base64_encode(s, strlen(s), mem, &outlen);
    //printf("base64\n%s\n", mem);
    zcheck(mem, __LINE__);
    
    int declen = base64_calc_decodelen(outlen);
    char *dmem = zalloc(declen);
    base64_decode(mem, outlen, dmem, &declen);
    //printf("dec base64\n%s\n", dec);
    //dump_mem(dmem, strlen(dmem));
    zcheck(dmem, __LINE__);
    
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
    err = gcry_pk_encrypt(&ciph, data, pubk);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

    gcry_mpi_t msg2;
    gcry_sexp_t data2;
    char *ss = strdup(s);
    ss[0] = 'J';
    err = gcry_mpi_scan(&msg2, GCRYMPI_FMT_USG, ss,
                        strlen((const char*) ss), NULL);

    err = gcry_sexp_build(&data2, NULL,
                           "(data (flags raw) (value %m))", msg2);
    if (err) {
        xerr("failed to create a sexp from the message");
    }
    gcry_sexp_t ciph2;
    err = gcry_pk_encrypt(&ciph2, data2, pubk);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

/* Decrypt the message. */
    gcry_sexp_t plain;
    err = gcry_pk_decrypt(&plain, ciph, privk);
    if (err) {
        xerr("gcrypt: decryption failed");
    }

    /* Pretty-print the results. */
    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    printf("Original:\n");
    gcry_mpi_dump(msg);

    unsigned char obuf[1280]; // = { 0 };
    memset(obuf, 'a', sizeof(obuf));
    
    printf("\n" "Cypher:\n");
    gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
    print_sexp(ddd);
    
    unsigned int plen = 0;
    const char *ptr = gcry_sexp_nth_data(ddd, 1, &plen);
    //dump_mem(ptr, plen);
    
    printf("\n" "Cypher2:\n");
    gcry_sexp_t ddd2 = gcry_sexp_find_token(ciph2, "a", 1);
    print_sexp(ddd2);
    
    unsigned int plen2 = 0;
    const char *ptr2 = gcry_sexp_nth_data(ddd2, 1, &plen2);
    //dump_mem(ptr2, plen2);
    
    printf("\n" "Decrypted:\n");
    gcry_mpi_dump(out_msg);
    printf("\n");

    if (gcry_mpi_cmp(msg, out_msg)) {
        xerr("data corruption!");
    }
    else {
        printf("Messages match.\n");
    }

    int written = 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char*) &obuf,
                         sizeof(obuf), &written, out_msg);
    if (err) {
        xerr("failed to stringify mpi");
    }
    
    obuf[written] = '\0';
    printf("-> %s\n", (char*) obuf);


    /* Release contexts. */
    gcry_mpi_release(msg);
    gcry_mpi_release(out_msg);
    //gcry_mpi_release(cri_msg);
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(pubk);
    gcry_sexp_release(privk);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);
    gcry_sexp_release(plain);
    gcry_cipher_close(aes_hd);
    free(rsa_buf);
    fclose(lockf);

    return 0;
}




