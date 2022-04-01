
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
#include <ctype.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

// -----------------------------------------------------------------------
// Unified strings for key files, definitons

const char *pub_start  = "-----BEGIN DIGIBANK RSA PUBLIC KEY-----";
const char *pub_end    = "-----END DIGIBANK RSA PUBLIC KEY-----";

const char *comp_start = "-----BEGIN DIGIBANK RSA COMPOSITE KEY-----";
const char *comp_end   = "-----END DIGIBANK RSA COMPOSITE KEY-----";

const char *cyph_start = "-----BEGIN DIGIBANK RSA CYPHER-----";
const char *cyph_end   = "-----END DIGIBANK RSA CYPHER-----";

const char *mod_start  = "-----BEGIN RSA PUBLIC MODULUS-----";
const char *mod_end    = "-----END RSA PUBLIC MODULUS-----";
    
const char *exp_start  = "-----BEGIN RSA PUBLIC EXPONENT-----";
const char *exp_end    = "-----END RSA PUBLIC EXPONENT-----";
    
void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(2);                                
}

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

void printerr(int err, char *str)

{
    if(str)
        fprintf (stderr, "%s\n", str);
        
    fprintf (stderr, "Failure: %s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
                        
    //fprintf (stdout, "Failure: %s/%s\n",
    //                gcry_strsource (err),
    //                    gcry_strerror (err));
}       

//////////////////////////////////////////////////////////////////////////

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

void get_aes_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];
    
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
// Print sexp to memory
// Free the resulting pointer

char *sprint_sexp(gcry_sexp_t sexp, int *len, int format)

{
    int slen = gcry_sexp_sprint(sexp, format, NULL, 0);
    *len = 0;
    zline2(__LINE__, __FILE__);
    char *ppp = (char*)zalloc(slen+1);
    if(ppp == NULL)
        return NULL;
    
    gcry_sexp_sprint(sexp, format, ppp, slen);
    *len = slen;
    // Zero terminate
    ppp[slen-1] = '\0';
    return(ppp);
}    

//////////////////////////////////////////////////////////////////////////
// Print sexp to stdout

void print_sexp(gcry_sexp_t rsa_keypair)

{
    int len;
    char *ppp = sprint_sexp(rsa_keypair, &len, GCRYSEXP_FMT_ADVANCED);
    if(ppp == NULL)
        return;
    printf("%s\n", ppp);
    zfree(ppp);
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

//////////////////////////////////////////////////////////////////////////
// Return file size

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);
    
    return  file_len;
}

//////////////////////////////////////////////////////////////////////////
// Return an allocated base 64 line limited string.
// Must use zfree to free

char *baselim(const char *mem, int len)
{
    int outlen = base64_calc_encodelen(len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    base64_encode(mem, len, mem2, &outlen);
    zcheck(mem2, __LINE__);             
    zline2(__LINE__, __FILE__);
    
    int linelen = 64;
    int limlen = outlen + 4 + outlen / linelen ;
    char *mem3 = zalloc(limlen);        
    base64_limline(mem2, outlen, mem3, &limlen, linelen);
    zfree(mem2);
    
    return mem3;
}

// Helper for command line

static char tmp_error[MAX_PATH];

static int parse_one(const char *str, opts popts_data[], int idx)

{
    int ret = 0;
    
    if(popts_data[idx].strval != NULL)
        {
        if(str == NULL)
            {   
            return -1;
            }
        strncpy(popts_data[idx].strval, str, MAX_PATH);
        ret = 1;
        }
    else if(popts_data[idx].val != NULL)
        {
        int val = atoi(str);
        if(popts_data[idx].minval > val ||
                popts_data[idx].maxval < val) 
            {
            return -1;
            }
        *popts_data[idx].val =  val;
        ret = 1;
        } 
    else if(popts_data[idx].flag != NULL)
        {
        *popts_data[idx].flag = TRUE;
        }
    return ret;
}    

/*
 * Read command line switches, set globals.
 *
 * In:      Arguments, procession options, place for error str
 * Out:     Args parsed
 * Return:  Last index processed
 # Pointer to an error message or NULL
 *
 */

int     parse_commad_line(char **argv, opts *popts_data, char **err_str)

{
    int     got, nn, processed = 0, err = 0;
    char    *ret_val = NULL;
    int     inval_arg = 0;

    *err_str = NULL;
    
    for (nn = 1; argv[nn] != NULL; nn++)
        {
        got = 0;
        // Long option?
        if(strlen(argv[nn]) > 2 && (argv[nn][0] == '-' && argv[nn][1] == '-'))
            {
            char *cmdstr = &argv[nn][2];
            //printf("Long option: '%s'\n", cmdstr);
            int idx = 0;
            if(strcmp(cmdstr, "help") == 0)
                {
                *err_str = "Help requested, long form.";
                return nn;
                }
            while(TRUE)
                {
                if(popts_data[idx].long_opt == NULL && popts_data[idx].opt == 0)
                    {
                    if(got == 0)
                        {
                        err++;
                        inval_arg = nn;
                        }
                    else
                        processed++;                        
                    break;
                    } 
                if(strcmp(popts_data[idx].long_opt, cmdstr) == 0)
                    {
                    //printf("Found long option %s arg %s\n", cmdstr, argv[nn]);
                    int ret = parse_one(argv[nn+1], popts_data, idx);
                    if(ret < 0)
                        { 
                        snprintf(tmp_error, sizeof(tmp_error), 
                            "Invalid value on option '--%s'\n", cmdstr);
                        *err_str = tmp_error;
                        return nn;
                        }
                    processed += ret;
                    got++;
                    }
                idx++;
                }
            }
        else if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            int idx = 0;
            //char cmd = tolower(argv[nn][1]); // made it case sensitive
            char cmd = argv[nn][1];
            if(cmd == '?' || cmd == 'h')
                {
                *err_str = "Help requested.";
                return nn;
                }
            while(TRUE)
                {
                if(popts_data[idx].long_opt == NULL && popts_data[idx].opt == 0)                    {
                    if(got == 0)
                        {
                        inval_arg = nn;
                        err++;
                        }
                    else
                        processed++;                        
                    break;
                    }   
                if(popts_data[idx].opt == cmd)
                    {
                    //printf("Got command %c\n", cmd);
                    got++;
                    int ret = 0; 
                    if(strlen(argv[nn]) > 2)
                        {
                        // Option in line
                        parse_one(&argv[nn][2], popts_data, idx);
                        }
                    else
                        {
                        // Next command is option  value
                        ret = parse_one(argv[nn+1], popts_data, idx);
                        if(ret < 0)
                            { 
                            snprintf(tmp_error, sizeof(tmp_error), 
                                "Invalid value on option '-%c'\n", cmd);
                            *err_str = tmp_error;
                            return nn;
                            }
                        }
                    processed += ret;
                    }
                 idx++;
                }
            }                 
        }
    if (err)
        {
        snprintf(tmp_error, sizeof(tmp_error), 
                   "Invalid option on command line '%s'\n", argv[inval_arg]);    
        *err_str = tmp_error;
        }
    return(processed);
}

void    usage(const char *progname, opts *opts_data)

{
    int  idx = 0, ret_val = 0;
    
    //printf("opts_data %s", opts_data);
    
    printf("\
\n\
Usage: %s\n\
Options can be:     \n\
", progname);

   while(TRUE)
        {
        if(opts_data[idx].opt == 0)
            break;
            
        printf("               %s\n", opts_data[idx].help);
        idx++;
        }
    printf("\n");
    printf(    "               -?                                     - displays this help\n");
    printf(    "               -h             --help                  - displays this help\n");
    printf(    "One option per item, last option prevails.\n");
}

typedef struct _armor_params
{
    char    *rsa_buf;
    int     *prsa_len;
    char    **err_str; 
    int     *cleanlen;
    const   char *starts; 
    const   char *ends;
}
armor_params;

static char *decode_armor(armor_params *params)

{
    char *sbegin = strstr(params->rsa_buf, params->starts);
    if(sbegin == NULL)
        {
        *params->err_str = "No start marker";
        return(NULL);
        }
    char *send   = strstr(params->rsa_buf, params->ends);
    if(send == NULL)
        {
        *params->err_str = "No end marker";
        return(NULL);
        }
    sbegin += strlen(params->starts) + 1;
    int slen = send - sbegin - 1;
    *params->cleanlen = slen;
    return sbegin;
} 

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts = pub_start;   params.ends = pub_end;

    char *sbegin = decode_armor(&params);
              
    int cleanlen = slen;
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}
            
//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_priv_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts = comp_start;  params.ends = comp_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return(NULL);
                            
    int cleanlen = slen;
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

void    print_cypher_details(const char *str)

{
    int cy = gcry_cipher_map_name(str);
    printf("Cypher:       %d\n", cy);
    printf("Cypher name:  '%s'\n", gcry_cipher_algo_name(cy));
    printf("Blocklen:     %d\n", gcry_cipher_get_algo_blklen(cy));
    printf("Keylen:       %d\n", gcry_cipher_get_algo_keylen(cy));
    printf("\n");
}    

//////////////////////////////////////////////////////////////////////////

int pk_encrypt_buffer(const char *buf, int len, gcry_sexp_t pubk, gcry_sexp_t *ciph)

{ 
    int ret = 0;
            
    /* Create a message. */
    gcry_mpi_t msg; 
    gcry_error_t err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buf, len, NULL);

    if (err) {
        printerr(err, "create mpi");
        //xerr("failed to create a mpi from the buffer");
    }

    gcry_sexp_t data; 
    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", msg);
    if (err) {
        printerr(err, "build");
        //xerr("failed to create a sexp from the message");
    }

    /* Encrypt the message. */
    err = gcry_pk_encrypt(ciph, data, pubk);
    if (err) {
            print_sexp(*ciph);
            printerr(err, "encryption");
        //xerr("gcrypt: encryption failed");
    }
    
    gcry_sexp_release(data);
    gcry_mpi_release(msg);
    ret = err;
    return ret;
}

//////////////////////////////////////////////////////////////////////////

int write_pubkey(gcry_sexp_t *rsa_keypair, const char *xfname2, const char *xfname3)

{
    gcry_sexp_t pubk = gcry_sexp_find_token(*rsa_keypair, "public-key", 0);
    int klen;
    //char *kptr = sprint_sexp(pubk, &klen, GCRYSEXP_FMT_ADVANCED);
    char *kptr = sprint_sexp(pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
       xerr("sprint failed");                                                              
    }
    char *mem5 = baselim(kptr, klen);
    
    FILE* lockf3 = fopen(xfname2, "wb");
    if (!lockf3) {
        {
        //xerr("fopen() failed");                                                              
        printf("Could not write publick key %s\n", xfname2);
        }
    }
    fprintf(lockf3, "%s\n", pub_start);
    fprintf(lockf3, "%s\n", mem5);
    fprintf(lockf3, "%s\n", pub_end);
    
    fclose(lockf3); 
    zfree(mem5);
    zfree(kptr);
    
    gcry_sexp_t nnn = gcry_sexp_find_token(*rsa_keypair, "n", 0);
    //print_sexp(nnn);
    unsigned int pklen = 0;
    const char *pkptr = gcry_sexp_nth_data(nnn, 1, &pklen);
    //dump_mem(ptr, pklen);
    
    gcry_sexp_t eee = gcry_sexp_find_token(*rsa_keypair, "e", 0);
    //print_sexp(eee);
    unsigned int elen = 0;
    const char *eptr = gcry_sexp_nth_data(eee, 1, &elen);
         
    FILE* lockf2 = fopen(xfname3, "wb");
    if (!lockf2) {
        printf("Could not write publick key %s\n", xfname3);
        //xerr("fopen() failed");                                                              
    }
    zline2(__LINE__, __FILE__);
    //fprintf(lockf2, "%s\n", comp_start);
    //printf("kptr %p klen %d\n", kptr, klen);
    zline2(__LINE__, __FILE__);
    char *mem3 = baselim(pkptr, pklen);
    fprintf(lockf2, "%s\n", mod_start);
    fprintf(lockf2, "%s\n", mem3);
    fprintf(lockf2, "%s\n", mod_end);
    zline2(__LINE__, __FILE__);
    char *mem4 = baselim(eptr, elen);
    fprintf(lockf2, "%s\n", exp_start);
    fprintf(lockf2, "%s\n", mem4);
    fprintf(lockf2, "%s\n", exp_end);
  
    //fprintf(lockf2, "%s\n", comp_end);
  
    fclose(lockf2);
    //zfree(kptr);
    zfree(mem3);
    zfree(mem4);
        
    return 0;
}














