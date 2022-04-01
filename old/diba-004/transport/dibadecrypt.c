
/* =====[ asdecrypt.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "gsexp.h"
#include "cmdline.h"

#include "bluepoint2.h"

static int verbose = 0;
static int test = 0;
static int ppub = 0;
static int nocrypt = 0;
static int use_stdin = 0;

static char    *infile   = NULL;
static char    *outfile  = NULL;
static char    *keyfile  = NULL;
static char    *thispass = NULL;

char  descstr[] = "Decrypt file with Private key.\n";
char usestr[] = "asdecrypt [options] keyfile";

opts opts_data[] = {
                    'i',  "infile",  NULL, &infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - input file name",
                    
                    'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - output file name",
                   
                    'p',   "pass",   NULL,  &thispass, 0, 0,    NULL, 
                     "-p             --pass                 - pass in for key (testing only)",
                    
                    'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - key file name",

                    'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
                    "-r             --stdin                 - use stdin as input",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - test on",
                    
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt               - do not decypt private key",
                   
                    'x',   "printpub",  NULL,  NULL, 0, 0, &ppub, 
                    "-x             --printpub              - print public key",
                    
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };


static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

char *mstr = "No Memory";

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);

    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
    infile   = zalloc(MAX_PATH); if(infile == NULL) xerr(mstr);
    outfile  = zalloc(MAX_PATH); if(outfile == NULL) xerr(mstr);
    keyfile  = zalloc(MAX_PATH); if(keyfile == NULL) xerr(mstr);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }

    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("Missing argument for ascrypt.");
        usage(usestr, descstr, opts_data); exit(2);
    }

    if(verbose)
        {
        printf("infile='%s' outfile='%s' keyfile='%s'\n", infile, outfile, keyfile);
        }
    
    //zverbose(TRUE);
    //gcry_set_allocation_handler(zalloc, NULL, NULL, zrealloc, zfree);
    
    gcrypt_init();
    gcry_error_t err;
    
    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], MAX_PATH);
        } 

    FILE* lockf = fopen(keyfile, "rb");
    if (!lockf) {
        xerr2("Opening of composite key failed on file '%s'.", keyfile);
    }
    
    /* Read and decrypt the key pair from disk. */
    unsigned int flen = getfsize(lockf);
    zline2(__LINE__, __FILE__);
    char* fbuf = zalloc(flen + 1);
    if (!fbuf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    if (fread(fbuf, flen, 1, lockf) != 1) {
        xerr2("Reading of composite key failed on file '%s'.", keyfile);
    }
    fclose(lockf);
    
    //fbuf[flen] = '\0';
    zcheck(fbuf, __LINE__);
    
    zline2(__LINE__, __FILE__);
    int  rsa_len = flen;
    char *rsa_buf = decode_comp_key(fbuf, &rsa_len, &err_str);
    zfree(fbuf);
    
    if (!rsa_buf) {
        //printf("%s\n", err_str);
        xerr2("Decode key failed. %s", err_str);
    }
    
    gcry_sexp_t compkey;
    err = gcry_sexp_new(&compkey, rsa_buf, rsa_len, 1);
    
    if (!compkey) {
        //printf("%s\n", err_str);
        xerr2("No composite key in this file.");
    }
    //print_sexp(compkey);
    /* Grab a key pair password */
    if(thispass[0] == '\0' && !nocrypt)
        {
        //getpass2(thispass, MAXPASSLEN, TRUE, TRUE);
        getpassx  passx;
        passx.prompt  = "Enter keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAXPASSLEN;
        passx.minlen = 3;
        passx.weak   = TRUE;
        passx.nodouble = TRUE;
        passx.strength = 4;
        int ret = getpass2(&passx);
        if(ret < 0)
            xerr("Error on password entry.");
        }
    else
        {
        // See if the user provided a file
        if(thispass[0] == '@')
            {
            char *passfile = &thispass[1];
            //printf("File on command line '%s'\n", passfile);
            FILE *fp = fopen(passfile, "rb");
            if(fp == NULL) {
                xerr2("Cannot open pass file '%s'\n", passfile);
                }
            unsigned int pass_len = getfsize(fp);
            zline2(__LINE__, __FILE__);
            char* pass_buf = zalloc(pass_len + 1);
            if (!pass_buf) {
                fclose(fp);
                xerr("malloc: could not allocate password file buffer");
                }
            if (fread(pass_buf, pass_len, 1, fp) != 1) {
                fclose(fp);
                xerr("Cannot read password from file.");
                }
            // Terminate at the end of line
            char *found = strstr(pass_buf, "\n");
            if (found != NULL)
                {
                *found = '\0';
                }
            
            // Put it back where it is expected
            strncpy(thispass, pass_buf, MAX_PATH);
            fclose(fp);
            zfree(pass_buf);
            }
        }
            
    //printf("thispass '%s'\n", t   hispass);
    
    gcry_sexp_t privkid = gcry_sexp_find_token(compkey, "private-crypted", 0);
    if(privkid == NULL)
        {
        xerr("No key found in private composite key.");
        }
        
    unsigned int plen3;
    char *buff3 = gcry_sexp_nth_buffer(privkid, 1, &plen3);
    
    if(!nocrypt)
    {
        // Decrypt buffer
        
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        err = gcry_cipher_decrypt(fish_hd, (unsigned char*) buff3, 
                                  plen3, NULL, 0);
        if (err) {
            xerr("gcrypt: could not encrypt with TWOFISH");
            }
        
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, thispass, strlen(thispass));
        
        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) buff3,
                                  plen3, NULL, 0);
        if (err) {
            xerr("gcrypt: failed to decrypt key pair");
        }
        gcry_cipher_close(fish_hd);
        gcry_cipher_close(aes_hd);
        
    }
    
    /* Load the key pair components into sexps. */
    gcry_sexp_t rsa_keypair;
    err = gcry_sexp_new(&rsa_keypair, buff3, plen3, 0);
    if(err)
        {
        // Delay a little to fool DOS attacks
        struct timespec ts = {0, 300000000};
        nanosleep(&ts, NULL);
        xerr2("Failed to load composite key. (pass?)");
        }
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(privk == NULL)
        {                           
        xerr2("No private key present in '%s'", keyfile);
        }
    //print_sexp(privk);
        
    zline2(__LINE__, __FILE__);
    int keylen =  gcry_pk_get_nbits(privk) / 8 ;
    //printf("Key length : %d\n", keylen);
    
    char *data_buf = NULL;
    unsigned int data_len;
    
    if(use_stdin)
        {
        //printf("Using stdin\n");
        zline2(__LINE__, __FILE__);
        char *fbuf2 = zalloc(20000);
        int  xidx = 0;
        while(TRUE)
            {
            char chh = getc(stdin);
            if(feof(stdin))
                {
                data_len = xidx;
                break;
                }
            fbuf2[xidx++] = chh;
            if(xidx > 10000)
                xerr("Out of preallocated stdin buffer\n");
            }
            
        //printf("Got stdin buffer %d byte\n%s\n", data_len, fbuf2);
            
        char *err_str;
        data_buf  = decode_rsa_cyph(fbuf2, &data_len, &err_str);
        if(!data_buf)
            {
            xerr2("Cannot decode input file. %s\n", err_str);
            }
        zfree(fbuf2); 
        }
    else if(infile[0] != '\0')
       {
        FILE* lockf2 = fopen(infile, "rb");
        if (!lockf2) {
            xerr2("Cannot open input file '%s'.", infile);
        }
        
        /* Read and decrypt the key pair from disk. */
        data_len = getfsize(lockf2);
        zline2(__LINE__, __FILE__);
        char* fbuf2 = zalloc(data_len + 1);
        if (!fbuf2) {
            xerr("Could not allocate plain text buffer");
        }
        if (fread(fbuf2, data_len, 1, lockf2) != 1) {
            xerr("Cannot reead input data.");
        }
        fclose(lockf2);
        
        char *err_str;
        data_buf  = decode_rsa_cyph(fbuf2, &data_len, &err_str);
        if(!data_buf)
            {
            xerr2("Cannot decode input file. %s\n", err_str);
            }
        zfree(fbuf2);     
       }
    else
        {
        xerr("Need data to decrypt.\n");
        }
        
    
    char *bpass = "1234";
    int bret = bluepoint2_decrypt(data_buf, data_len, bpass, strlen(bpass));

    int  outlen2 = 0;
    zline2(__LINE__, __FILE__);
    int lim_len =  data_len * 2 + keylen;
    char *outptr = zalloc(lim_len);
    if(!outptr)
        {
        xerr("Cannot allocate output memory.");
        }
    
    int loop = 0;
    char pub_hash[32];
    // Get key hash out of the way
    short hash_len = *( (short*) (data_buf + loop) );
    loop += sizeof(short);   
    memcpy(pub_hash, data_buf + loop, sizeof(pub_hash));
    loop += hash_len;
    if(loop >= data_len)
        xerr("Reading past end of data. (possible data corruption)");    
        
    // Get key id out of the way
    short keyid_len = *( (short*) (data_buf + loop) );
    loop += sizeof(short);   loop += keyid_len;
    if(loop >= data_len)
        xerr("Reading past end of data. (possible data corruption)");    
    
     #if 0
    // Decrypt in place
    gcry_cipher_hd_t aes_hd2; char *keypass = "12345678";
    get_twofish_ctx(&aes_hd2, keypass, strlen(keypass));
    err = gcry_cipher_decrypt(aes_hd2, (unsigned char*) data_buf + sizeof(short),
                              keyid_len, NULL, 0);
    if (err) {
        xerr("gcrypt: failed to decrypt key id");
        }
    gcry_cipher_close(aes_hd2);
    #endif
    
    //printf("Key ID from cypher: '%.*s'\n", keyid_len, data_buf + sizeof(short) + sizeof(int)); 
    
         
    for(; loop < data_len; /* loop += keylen */)
        {
        short curr_len = *( (short*) (data_buf + loop) );
        loop += sizeof(short);
        //printf("data %p len = %d ", data_buf + loop, curr_len);
        
        if(loop + curr_len > data_len)
            {
            xerr2("Reading past last byte.");
            }
        
        /* Create a message. */
        gcry_sexp_t ciph;
        int err_offs;
        gcry_error_t err2 = gcry_sexp_build(&ciph, NULL, 
                                    "(enc-val (rsa (a %b)))", 
                                        curr_len, data_buf + loop);
        //print_sexp(ciph);
        
        /* Decrypt the message. */
        gcry_sexp_t plain;
        err = gcry_pk_decrypt(&plain, ciph, privk);
        if (err) {
            xerr("gcrypt: decryption failed");
            }
    
        /* Pretty-print the results. */
        gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
        
        int plen = 0; unsigned char *buffm;                                     
        err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffm, &plen, out_msg);
        if (err) 
            {
            xerr("failed to stringify mpi");
            } 
        //printf("outlen %d\n", plen);
        
        if(outlen2 + plen > lim_len)
            {
            xerr("Could not write all mem to buffer");
            } 
        memcpy(outptr + outlen2, buffm + sizeof(int), plen - sizeof(int)); 
        outlen2 += plen - sizeof(int);
        loop += curr_len;
        }
        
    char pub_hash2[32];
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash2, 
                    (const void*) outptr, outlen2);
    
    if (memcmp(pub_hash, pub_hash2, 32) != 0)
        {
        xerr("The hash of the decrypted file does not match the origina.l");
        }
        
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr("Cannnot open outfile");
            }
        }
    int retf = fwrite(outptr, outlen2, 1, outf); 
    if(retf != 1)
        {
        xerr("Cannot write to file");
        }
    if(outf != stdout)
        {
        fclose(outf);
        }
        
    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(privk);
    
    zline2(__LINE__, __FILE__);
    zfree(outptr);
    zline2(__LINE__, __FILE__);
    zfree(data_buf);
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);
    zline2(__LINE__, __FILE__);
    zfree(dummy);
    
    zfree(infile);  
    zfree(outfile); 
    zfree(keyfile);
    zfree(thispass);
    
    zleak();
    
    return 0;
}

/* EOF */









