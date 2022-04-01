
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
#include <string.h>
#include <ctype.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

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

//////////////////////////////////////////////////////////////////////////

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

void get_twofish_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];
    
    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_TWOFISH, 
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
    sbegin += strlen(params->starts);
    int slen = send - sbegin;
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
    params.starts =  pub_start;   params.ends    = pub_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
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

char *decode_rsa_cyph(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  cyph_start; params.ends     = cyph_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);
    zcheck(memc, __LINE__);
    
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

char *decode_comp_key(char *rsa_buf, int *prsa_len, char **err_str)

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
    zline2(__LINE__, __FILE__);
    
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

int write_pubkey(gcry_sexp_t *pubk, const char *fname2)

{
    int ret = TRUE;
    int klen;
    
    char *kptr = sprint_sexp(*pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
       //xerr2("sprint failed. %s %d", __FILE__, __LINE__);                                                              
        printf("Could not sprint S exp for %s\n", fname2);
        return -1;
    }
    int outx;
    char *mem5 = base_and_lim(kptr, klen, &outx);
    mem5[outx] = '\0';
    
    FILE* fp3 = fopen(fname2, "wb");
    if (!fp3) {
        {
        //xerr("fopen() failed");                                                              
        printf("Could not write publick key %s\n", fname2);
        return -1;
        }
    }
    fprintf(fp3, "%s\n", pub_start);
    fprintf(fp3, "%.*s\n", outx, mem5);
    fprintf(fp3, "%s\n", pub_end);
    
    fclose(fp3); 
    zfree(mem5);
    zfree(kptr);
    
    return ret;
}    
    
int write_mod_exp(gcry_sexp_t *rsa_keypair, const char *fname2)

{
    int ret = TRUE;
    
    gcry_sexp_t nnn = gcry_sexp_find_token(*rsa_keypair, "n", 0);
    if(nnn == NULL)
        {
        printf("Could not find public modulus. (no .mod file written)\n");
        return -1;
        }
    //print_sexp(nnn);
    
    unsigned int pklen = 0;
    const char *pkptr = gcry_sexp_nth_data(nnn, 1, &pklen);
    //dump_mem(ptr, pklen);
    
    gcry_sexp_t eee = gcry_sexp_find_token(*rsa_keypair, "e", 0);
    if(eee == NULL)
        {
        printf("Could not find public expenent. (no .mod file written)\n");
        return -1;
        }
    //print_sexp(eee);
    unsigned int elen = 0;
    const char *eptr = gcry_sexp_nth_data(eee, 1, &elen);
         
    FILE* fp2 = fopen(fname2, "wb");
    if (!fp2) {
        printf("Could not write .mod file to %s\n", fname2);
        return -1;
        //xerr("fopen() failed");                                                              
    }
    int outx;
    zline2(__LINE__, __FILE__);
    char *mem3 = base_and_lim(pkptr, pklen, &outx);
    mem3[outx] = '\0';
    fprintf(fp2, "%s\n", mod_start);
    fprintf(fp2, "%.*s\n", outx, mem3);
    fprintf(fp2, "%s\n", mod_end);
    zline2(__LINE__, __FILE__);
    char *mem4 = base_and_lim(eptr, elen, &outx);
    mem4[outx] = '\0';
    fprintf(fp2, "%s\n", exp_start);
    fprintf(fp2, "%.*s\n", outx, mem4);
    fprintf(fp2, "%s\n", exp_end);
  
    fclose(fp2);
    zfree(mem3);
    zfree(mem4);
        
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Return an allocated base64 line limited string.
// Must use zfree to free pointer

char *base_and_lim(const char *mem, int len, int *olen)
{
    int outlen = base64_calc_encodelen(len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    int ret = base64_encode(mem, len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);             
    zline2(__LINE__, __FILE__);
    
    int linelen = 64, limlen = outlen + 4 + outlen / linelen ;
    char *mem3 = zalloc(limlen);        
    int ret2 = base64_limline(mem2, outlen, mem3, &limlen, linelen);
    zfree(mem2);
    if(ret2 < 0)
        return NULL;
    *olen = limlen;
    
    return mem3;
}

#if 0
      int  tm_sec;          /* Seconds: 0-60 (to accommodate leap seconds) */
      int  tm_min;          /* Minutes: 0-59 */
      int  tm_hour;         /* Hours since midnight: 0-23 */
      int  tm_mday;         /* Day of the month: 1-31 */
      int  tm_mon;          /* Months *since* January: 0-11 */
      int  tm_year;         /* Years since 1900 */
      int  tm_wday;         /* Days since Sunday (0-6) */
      int  tm_yday;         /* Days since Jan. 1: 0-365 */
      int  tm_isdst;        /* +1=Daylight Savings Time, 0=No DST, -1=unknown */
    #endif

//////////////////////////////////////////////////////////////////////////
// get user name, return pointer.
// must free with zfree

char *zusername()

{
    char *name = getenv("USERNAME");
    if(name == NULL) 
        name = "unknown name";
        
    int len = strlen(name);
    zline2(__LINE__, __FILE__);
    char *nnn = zalloc(len + 1);
    strncpy(nnn, name, len);
    nnn[len] = '\0';
    return nnn;
}

char *zhostname()

{
    char *name = getenv("USERDOMAIN");
    if(name == NULL) 
        name = "unknown host";
        
    int len = strlen(name);
    zline2(__LINE__, __FILE__);
    char *nnn = zalloc(len + 1);
    strncpy(nnn, name, len);
    nnn[len] = '\0';
    return nnn;
}

//////////////////////////////////////////////////////////////////////////
// get current date, return pointer.
// must free with zfree

char *zdatestr()

{
    int allocsize = 64;
    zline2(__LINE__, __FILE__);
    char *ttt = zalloc(allocsize);
    time_t tme = time(NULL);
    struct tm *tmm = localtime(&tme);
    int len = snprintf(ttt, allocsize, "%4d/%02d/%02d %02d:%02d:%02d", 
               tmm->tm_year + 1900, tmm->tm_mon + 1, tmm->tm_mday,
                tmm->tm_hour, tmm->tm_min, tmm->tm_sec );
    zcheck(ttt, __LINE__);
    return ttt;  
}

// Must free with zfree
    
char *zrandstr(int len)

{
    zline2(__LINE__, __FILE__);
    char *rrr = zalloc(len);
    gcry_randomize(rrr, len, GCRY_STRONG_RANDOM);
    //rrr[sizeof(rrr)-1] = '\0';
    int len2 = len;
    char *ret = tobase64(rrr, &len2);
    zcheck(rrr, __LINE__);
    zfree(rrr);
    return ret;
}    

// Must free with zfree

char *tobase64(char *mem, int *len)

{
    int outlen = base64_calc_encodelen(*len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    int ret = base64_encode(mem, *len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);             
    *len = outlen;
    return(mem2);    
}

//////////////////////////////////////////////////////////////////////////
// 

char *zstrcat(const char *str1, const char* str2)
{
    //printf("cat %s + %s\n", str1, str2);
    int len1 = strlen(str1), len2 = strlen(str2);
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(len1 + len2 + 4);
    strcpy(ret, str1);
    strcat(ret, str2);
    zcheck(ret, __LINE__);
    //printf("cat out %s\n", ret);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// 

char *zstrdup(const char *str1, int maxsize)

{
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(maxsize + 1);
    if(ret == NULL)
        return NULL;
    strncpy(ret, str1, maxsize);
    zcheck(ret, __LINE__);
    return ret;
}

// See if keysize has more than one bit set (if it is a power of two)

int  num_bits_set(unsigned int ks) 

{
    int bits = 0; 
    //printf("bits of %d (0x%x)\n", ks, ks);
    while(TRUE)
        {
        if(ks & 1)
            bits++;
        ks >>= 1;
        if (ks == 0)
            break;
        }  
    //printf("ks bits %d\n", bits);  
    return bits;
}   

//////////////////////////////////////////////////////////////////////////
// Return sha hash string

char *hash_file(char *fname, char **err_str)

{ 
    char pub_hash[32];
    
    //printf("Arg '%s'\n", argv[0]);
    FILE *fp = fopen(fname, "rb");
    if(fp == NULL) {
        *err_str = "Cannot open executable for hashing.";
        return(NULL);
        }
    unsigned int file_len = getfsize(fp);
    zline2(__LINE__, __FILE__);
    char* file_buf = zalloc(file_len + 1);
    if (!file_buf) {
        fclose(fp);
        *err_str = "malloc: could not allocate file buffer for hashing.";
        return(NULL);
        }
    if (fread(file_buf, file_len, 1, fp) != 1) {
        zfree(file_buf);
        fclose(fp);
        *err_str = "Cannot read self (exe) file for hashing.";
        return(NULL);
        }
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash, 
                    (const void*) file_buf, file_len);
    
    zfree(file_buf);
    int olen;
    char *hash_str = base_and_lim(pub_hash, sizeof(pub_hash), &olen);
    }
    
    
//////////////////////////////////////////////////////////////////////////
// Best execute at the beggining:

void rand_seed()

{
     // Up-seed the random number generator
    srand(time(NULL)); int sss = rand();  srand(sss);
    // Consume some numbers, random amont
    int ccc = rand() % 20 + 10;
    for(int loop = 0; loop < ccc; loop++)
        {
        rand();
        }
}

//////////////////////////////////////////////////////////////////////////
// The following section allocates a useless random amount of memory.
// This will assure that strings appear in different places between runs.

char    *alloc_rand_amount()

{
    char *dummy;
    rand_seed(); 
    int ttt = rand() % 900 + 100;
    //printf("Using rand memory size %d\n", ttt);
    
    zline2(__LINE__, __FILE__);
    dummy = zalloc(ttt);
    if(dummy == NULL)
        return NULL;
    // Fill it up with crap
    for(int loop = ttt / 4; loop < (3 * ttt) / 4; loop++)
        {
        //printf("%c", rand() % (128 - 32) + 32);
        dummy[loop] = rand() % (128 - 32) + 32;
        }
    return dummy;
 }    
        
/* EOF */
