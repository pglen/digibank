
/* =====[ asencrypt.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.
      0.00  aug.18.2017     Peter Glen      Added random sequence to buffer.

   ======================================================================= */

#include <signal.h>
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "gsexp.h"

#include "bluepoint2.h"

static int dump = 0;
static int verbose = 0;
static int test = 0;
static int ppub = 0;
static int use_stdin = 0;

static char    infile[MAX_PATH] = {'\0'};
static char    outfile[MAX_PATH] = {'\0'};
static char    keyfile[MAX_PATH] = {'\0'};

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'i',  "infile",  NULL, infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - input file name",
                    
                    'o',  "outfile",  NULL, outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - output file name",

                    'k',  "keyfile",  NULL, keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - key file name",

                    'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
                    "-r             --stdin                 - use stdin as input",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump                  - Dump buffers",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - test on",
                    
                    'b',   "ppub",  NULL,  NULL, 0, 0, &ppub, 
                    "-v             --ppub              - print public key",
                    
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };


char usestr[] = "asencrypt [options] keyfile";

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

//////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv)

{
    signal(SIGSEGV, myfunc);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, opts_data); exit(2);
        }

    if(verbose)
        {
        //printf("nn=%d  test=%d verbose=%d\n", nn, test, verbose);
        //printf("infile='%s' outfile='%s' keyfile='%s'\n", infile, outfile, keyfile);
        }
    
    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("Missing argument for ascrypt.");
        usage(usestr, opts_data); exit(2);
    }

    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], sizeof(keyfile));
        } 
    
    //zverbose(1);
    gcrypt_init();
    gcry_error_t err;
    //char* fname = argv[nn + 1];
    
    FILE* lockf = fopen(keyfile, "rb");
    if (!lockf) {
        xerr2("Cannot open keyfile '%s'.", keyfile);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr("Cannot allocate rsa buffer.");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr("Cannot read public key.");
    }
    rsa_buf[rsa_len] = '\0';
    //printf("'%s'\n", rsa_buf);
    fclose(lockf);

    int outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key(rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        xerr2("Cannot decode public key: '%s'.", dec_err_str);
        }
        
    if(ppub)
        dump_mem(mem, outlen); 
        
    gcry_sexp_t pubkey;
    err = gcry_sexp_new(&pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        //printerr(err, "encrypt");
        xerr("Failed to read public key.");
        }
        
    if(ppub)
        print_sexp(pubkey);
    
    int keylen = gcry_pk_get_nbits(pubkey) / 8;
    //printf("keylen %d\n", keylen);
    
    char *buff2 = NULL;
    unsigned int plen2 = 0;
    gcry_sexp_t keyid = gcry_sexp_find_token(pubkey, "key-id", 0);
    if(keyid == NULL)
        {
        xerr("Public key has no keyid.");
        }
    char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen2);
    // Menas test
    if(plen2 < 0)
        xerr("Key length cannot be negative.");
    
    zline2(__LINE__, __FILE__);
    buff2 = zalloc(plen2 + 1);
    memcpy(buff2, buff, plen2);
    buff2[plen2] = '\0';
    gcry_free(buff);
    if(verbose)
        printf("Public KeyID '%s'\n", buff2); 
    
    /* Read in a buffer */
    char* data_buf;
    unsigned int  data_len;
    
    if(use_stdin)
        {
        int stdin_size = 20000;
        //printf("Using stdin\n");
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(stdin_size + 10);
        if(data_buf == NULL) {
            xerr("Cannot allocate data for stdin.");
            }
        int  xidx = 0;
        while(TRUE)
            {
            char chh = getc(stdin);
            if(feof(stdin))
                {
                data_len = xidx;
                break;
                }
            data_buf[xidx++] = chh;
            if(xidx > stdin_size)
                xerr2("Out of preallocated stdin buffer. (%d bytes)\n", stdin_size);
            }
        //printf("Got stdin buffer %d bytes:\n'%s'\n", data_len, data_buf);
        }
    else if(strlen(infile))
        {
        FILE* dataf = fopen(infile, "rb");
        if (!dataf) {
            xerr2("Cannot open data file: '%s'", infile);
            }
        data_len = getfsize(dataf);
        //printf("data file size %d\n", rsa_len);
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(data_len + 1);
        if (!data_buf) {
            xerr("Cannot allocate data buffer.");
            }
        if (fread(data_buf, data_len, 1, dataf) != 1) {
            xerr2("Cannot read data file '%s'.", infile);
            }
        }
    else
        {        
        xerr("No data specified for encryption");
        }
    
    int  outlen2 = 0;
    int outlim = data_len * 2 + keylen * 2 + plen2 + sizeof(int) + 1;
    zline2(__LINE__, __FILE__);
    char *outptr = zalloc(outlim);
    if(!outptr)
        {
        xerr("Cannot allocate memory");
        }
        
    // Start with the key id
    // short  int   varlen
    // Len + rand + keyid 
    //       |-----------| => encrypt
    
    *( (short *)(outptr)) = (short) (plen2 & 0xffff) + sizeof(int);
    gcry_randomize((outptr + sizeof(short)), sizeof(int), GCRY_STRONG_RANDOM);
    memcpy(outptr + sizeof(short) + sizeof(int), buff2, plen2); 
    
    #if 0
    // Encrypt in place
    gcry_cipher_hd_t aes_hd2; char *keypass = "12345678";
    get_twofish_ctx(&aes_hd2, keypass, strlen(keypass));
    err = gcry_cipher_encrypt(aes_hd2, (unsigned char*) outptr + sizeof(short),
                              plen2 + sizeof(int), NULL, 0);
    if (err) {
        xerr("Failed to encrypt key id.");
        }
    gcry_cipher_close(aes_hd2);
    #endif
    
    zfree(buff2);
    
    outlen2 += sizeof(short); 
    outlen2 += sizeof(int); 
    outlen2 += plen2;
        
    // Create the message. 
    // Parse keylen - sizeof(int) chunks, add 4 bytes of random 
    // Padd last chunk with zeros 
    
    int blocklen = keylen - sizeof(int);  
    
    zline2(__LINE__, __FILE__);
    char *tmp_buf = zalloc(keylen + 1);
    for(int loop = 0; loop < data_len; loop += blocklen)
        {
        int curr_len = blocklen;
        if(data_len - loop < blocklen)
            {
            curr_len = data_len - loop;
            }
        //printf("data %p len = %d ", data_buf + loop, curr_len);
        gcry_randomize(tmp_buf, sizeof(int), GCRY_STRONG_RANDOM);
        memcpy(tmp_buf + sizeof(int), data_buf + loop, curr_len + sizeof(int));
        
        gcry_mpi_t msg;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, tmp_buf,
                            curr_len + sizeof(int), NULL);
    
        if (err) {
            xerr("Failed to create a mpi from the message.");
        }
        
        gcry_sexp_t enc_data;
        err = gcry_sexp_build(&enc_data, NULL,
                               "(data (flags raw) (value %m))", msg);
                               
        if (err) {
            //printerr(err, "bulding sexp");
            xerr("Failed to create a sexp from the message.");
        }
        
        /* Encrypt the message. */
        gcry_sexp_t ciph;
        err = gcry_pk_encrypt(&ciph, enc_data, pubkey);
        if (err) {
            //printerr(err, "encryption");
            xerr("Encryption failed.");
        }
        
        gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
        //print_sexp(ddd);
        
        if(ddd == NULL)
        if (err) {
            xerr("Internal: find token failed");
        }
        
        unsigned int plen = 0;
        const char *dptr = gcry_sexp_nth_data(ddd, 1, &plen);
        
        //printf("outlen %d\n", plen);
        if(dump)
            {
            //printf("Output:\n");
            dump_mem(dptr, plen);
            }
        // Add to our cummulative buffer
        
        if(outlen2 + plen > outlim)
            {
            xerr("Could not write all mem to buffer.");
            }
        *( (short *)(outptr + outlen2)) = (short) plen & 0xffff;
        outlen2 += sizeof(short); 
        memcpy(outptr + outlen2, dptr, plen); 
        outlen2 += plen;
            
        /* Release contexts. */
        gcry_mpi_release(msg);
        gcry_sexp_release(enc_data);
        gcry_sexp_release(ciph);
        }      
    zfree(tmp_buf);    
    
    char *bpass = "1234";
    int bret = bluepoint2_encrypt(outptr, outlen2, bpass, strlen(bpass));

    int outx, plen;
    char *mem3 = base_and_lim(outptr, outlen2, &outx);
    
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr2("Cannnot create outfile '%s'.", outfile);
            }
        }
    int fullen =  strlen(cyph_start) + strlen(cyph_start) + outx + 10;
    zline2(__LINE__, __FILE__);
    char *mem4 = zalloc(fullen);
    if(!mem4) 
        xerr("Cannot allocate memory for output.");
    
    int add = snprintf(mem4, fullen, "%s\n", cyph_start);
    add += snprintf(mem4 + add, fullen - add, "%.*s\n", outx, mem3);
    add += snprintf(mem4 + add, fullen - add, "%s\n", cyph_end);
    
    //dump_mem(mem4, add);
    int retf = fwrite(mem4, add, 1, outf); 
    if(retf != 1)
        {
        xerr2("Cannot write to output file '%s'.", outfile);
        }
    
    zfree(mem4);
    
    //fprintf(outf, "%s\n", cyph_start);
    //fprintf(outf, "%*s\n", outx, mem3);
    //fprintf(outf, "%s\n", cyph_end);
    
    if(outf != stdout)
        {
        fclose(outf);
        }
        
    zfree(mem3);
    zfree(data_buf);
    
    /* Release contexts. */
    gcry_sexp_release(pubkey);
    
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);
    zline2(__LINE__, __FILE__);
    zfree(outptr);
    
    zleak();
    return 0;
}

/* EOF */






















