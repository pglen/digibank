
/* =====[ dibakeygen.c ]=========================================================

   Description:     Key generation for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.10.2017     Peter Glen      Moved to DIBA
      0.00  aug.23.2017     Peter Glen      Version info added 

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"

static  unsigned int keysize = 2048;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int calcsum = 0;
static int nocrypt = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Generate Public / Private keypair into a set of key files.";

static char usestr[] = "dibakeygen [options] keyfile\n"
                "Where 'keyfile' is the basename for .key .pub files. [keyfile.pub, keyfile.key]";
                
static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'k',   "keylen",   &keysize,  NULL,  1024, 32768,    NULL, 
        "-k             --keylen      - key length in bits (default 2048)",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
        
        'u',   "dump",  NULL, NULL,  0, 0,    &dump, 
        "-u             --dump        - Dump key to terminal",
        
        't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test        - run self test before proceeding",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - print sha sum before proceeding",
        
        'f',   "force",  NULL,  NULL, 0, 0, &force, 
        "-f             --force       - force clobbering files",
        
        'w',   "weak",  NULL,  NULL, 0, 0, &weak, 
        "-w             --weak        - allow weak pass",
        
        'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
        "-n             --nocrypt     - do not encrypt key (testing only)",
       
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val    - pass in for key (@file reads pass from file)",
        
        'm',   "keyname",  NULL,   &keyname, 0, 0, NULL, 
        "-m name        --keyname nm  - user legible key name",
       
        'd',   "desc",  NULL,      &keydesc, 0, 0, NULL, 
        "-d desc        --desc  desc  - key description",
       
        'c',   "creator",  NULL,   &creator, 0, 0, NULL, 
        "-c name        --creator nm  - override creator name (def: logon name)",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname == NULL)  xerr(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc == NULL)  xerr(mstr);
    creator  = zalloc(MAX_PATH); if(creator == NULL)  xerr(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    //printf("Processed %d comline entries\n", nn);
    
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    if(version)
        {
        printf("dibakeygen version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    
    if (argc - nn != 2) {
        //fprintf(stderr, "Usage: dibakeygen.exe outfile\n");
        //xerr("Invalid arguments.");
        printf("No keyfile specified.\n");
        usage(usestr, descstr, opts_data); exit(2);
    }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr("\nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    //if(keysize % 2 )
    //    {
    //    xerr2("Keysize must be even %d", keysize);
    //    }
        
    if(num_bits_set(keysize) != 1)
        {
        xerr2("Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
    
    gcrypt_init();

    if(test)
        {
        printf("Excuting self tests ... ");
        gcry_error_t err = 0;
        err = gcry_control(GCRYCTL_SELFTEST);
        if(err)
            {
            printf("fail.\n");
            exit(3);
            }
        else
            {
            printf("pass.\n");
            }
        }
   
    if(calcsum)
        {
        char *err_str;
        char *hash_str = hash_file(argv[0], &err_str);
        if(hash_str)
            {
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr2("%s\n", err_str);
            }
        }
        
    char* fname = zstrcat(argv[nn+1], ".key");
    //printf("fname %s\n", fname);
    char* fname2 = zstrcat(argv[nn+1], ".pub");
    //printf("fname2 %s\n", fname2);
    
    //char* fname3 = zstrcat(argv[nn+1], ".mod");
    //printf("fname3 %s\n", fname3);
    
    if(access(fname, F_OK) >= 0 && !force)
        {
        xerr("File already exists, use different name or delete the file or use -f (--force) option.");
        }
        
    /* Generate a new RSA key pair. */
    printf("\nRSA key generation (of %d bits) can take a few minutes. Your computer "
           "needs to gather random entropy.\n\n", keysize);
    printf("Please wait ");

    gcry_set_progress_handler(my_progress_handler, NULL);

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;
    
    char *key_str = zalloc(64); 
    snprintf(key_str, 64, "(genkey (rsa (nbits 4:%d)))", keysize);
    err = gcry_sexp_build(&rsa_parms, NULL, key_str);
    zfree(key_str);
    if (err) {
        printerr(err, "create rsa params");
        xerr("Failed to create rsa params");
    }
    
    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        printerr(err, "create keypair");
        xerr("Failed to create rsa key pair");
    }
    memset(key_str, sizeof(key_str), '\0'); 
        
    printf("\n\nRSA key generation complete.\n\n");
    
    /* Grab a key pair password and create an encryption context with it. */
        
    int ret = 0;
    if(thispass[0] == '\0' && !nocrypt)
        {
        printf("Please enter a password to lock your key pair.\n");
        printf("This password must be retained for later use. Do not loose this password.\n\n");
        if(weak)
            printf("Warning! Weak option specified, recommended for testing only.\n");
        getpassx  passx;
        passx.prompt  = "Enter  keypair  pass:";
        passx.prompt2 = "Confirm keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAX_PATH;
        passx.minlen = 4;
        passx.strength = 6;
        passx.weak = weak;
        passx.nodouble = FALSE;
        
        ret = getpass2(&passx);
        if(ret < 0)
            {
            xerr("Error on entering pass, no keys are written.\n");
            }
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
            //dump_mem(pass_buf, pass_len);
            // Put it back where it is expected
            strncpy(thispass, pass_buf, sizeof(thispass));
            fclose(fp);
            zfree(pass_buf);
            }
        }   
    //printf("thispass '%s'\n", thispass);
    
    char *ttt = zdatestr();
    char *user = zusername();
    char *host = zhostname();
    char *rrr  = zrandstr(24); 
    
    if(creator[0] != '\0')
        {
        zfree(user);
        user = zstrdup(creator, MAX_PATH);
        }
    char *keyver = zalloc(MAX_PATH);
    snprintf(keyver, MAX_PATH, "%d.%d.%d", ver_num_major, ver_num_minor, ver_num_rele);

    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    int olen;
    char *hash_str = hash_sexp(pubk, &olen);
    
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    char *hash_str2 = hash_sexp(privk, &olen);
    
    if(keyname[0] == '\0')
        strcpy(keyname, "unnamed key");
    if(keydesc[0] == '\0')
        strcpy(keydesc, "no description");
        
    gcry_sexp_t glib_keys;
    err = gcry_sexp_build(&glib_keys, NULL, 
                "(gcrypt-key (\"Key creation date\" %s) "
                    "(\"Key Version\" %s) (\"Key name\" %s) (\"Description\" %s)  "
                    "(\"Key ID\" %s) (\"Creator\" %s) (\"Hostname\" %s) "
                    "(\"Public file name\" %s)  (\"Public hash\" %s) "
                    "(\"Private file name\" %s) (\"Private hash\" %s) )",  
                        ttt, keyver, keyname, keydesc, rrr, user, host, 
                            fname, hash_str, fname2, hash_str2);
                         
    if(err)
        xerr2("Cannot create sexpr: '%s'\n", gcry_strerror (err));
      
    //print_sexp(glib_keys);
    
    zfree(keyver);                              
    zfree(hash_str); zfree(hash_str2); 
    
    if(verbose)
       list_sexp(glib_keys);
    
    gcry_sexp_t glib_pub;
    err = gcry_sexp_build(&glib_pub, NULL, "%S %S", glib_keys, pubk);
        
    if(write_pubkey(&glib_pub, fname2) < 0)
        xerr("Could not write pubic key");
    
    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(keysize);
    zline2(__LINE__, __FILE__);
    void* rsa_buf = zalloc(rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    
    rsa_len = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    //rsa_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    if(rsa_len == 0)
        {
        xerr("Cannot sprint keypair");
        }
        
    if(dump)
        dump_mem(rsa_buf, rsa_len);
        
    if(nocrypt)
        {
        printf("Warning: This key is unencrypted.\n");
        }
    else
        {
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, thispass, strlen(thispass));
        
        
        err = gcry_cipher_encrypt(aes_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr("Could not encrypt with AES");
            }
            
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        err = gcry_cipher_encrypt(fish_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr("Could not encrypt with TWOFISH");
            }
        gcry_cipher_close(aes_hd);
        gcry_cipher_close(fish_hd);
        }
    
    gcry_sexp_t glib_crypted;
    err = gcry_sexp_build(&glib_crypted, NULL, 
                "(private-crypted %b)", rsa_len, rsa_buf);
                
    //print_sexp(glib_crypted);
        
    gcry_sexp_t glib_priv;
    err = gcry_sexp_build(&glib_priv, NULL, "%S %S", glib_keys, glib_crypted);
    //print_sexp(glib_priv);
    
    int comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, NULL, 0);                
    zline2(__LINE__, __FILE__);
    char *comp_buf = zalloc(comp_len + 1);
    comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, comp_buf, comp_len);
                   
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr("fopen() failed");                                                              
    }
    ///* Write the encrypted base64 key pair to disk. */
    int limlen = comp_len;
    char *mem6 = base_and_lim(comp_buf, comp_len, &limlen);
   
    fprintf(lockf, "%s\n", comp_start);
    fprintf(lockf, "%*s\n", limlen, mem6);
    fprintf(lockf, "%s\n", comp_end);
    
    fclose(lockf);
    zfree(mem6);
    
    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    zfree(rsa_buf);
    zfree(comp_buf);
    
    printf("Key '%s'  successfully saved to '%s' and '%s'.\n", rrr, fname, fname2);
    zfree(ttt);  zfree(rrr); zfree(user); zfree(host);
    
    zfree(fname);       zfree(fname2);
    zfree(thispass);    zfree(keyname);      
    zfree(keydesc);     zfree(creator);
    
    zfree(dummy);
    
    zleak();
    return 0;
}

/* EOF */


