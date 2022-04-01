
/* =====[ asencrypt.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.
      0.00  aug.18.2017     Peter Glen      Added random sequence to buffer.
      0.00  aug.26.2017     Peter Glen      Shortened buffer passed to _pk_
      0.00  aug.26.2017     Peter Glen      First push to github

   ======================================================================= */

#include <signal.h>
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "gsexp.h"
#include "cmdline.h"
#include "dibastr.h"
#include "bluepoint2.h"

//#define TEST_PK
//#define TEST_BLUE

static int dump = 0;
static int verbose = 0;
static int test = 0;
static int ppub = 0;
static int use_stdin = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char    *infile  = NULL;
static char    *outfile = NULL;
static char    *keyfile = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'i',  "infile",  NULL, &infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - input file name",
                    
                    'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - output file name",

                    'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - key file name",

                    'V',   "version",  NULL, NULL,  0, 0, &version, 
                    "-V             --version     - Print version numbers and exit",
                            'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
                    "-r             --stdin                 - use stdin as input",

                   's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
                    "-s             --sum         - print sha sum before proceeding",
                    
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


char descstr[] = "Encrypt files with Public key\n";
char usestr[] = "asencrypt [options] keyfile";

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static void log_func(void *my, int val, const char *str, va_list va)

{
    //printf("From logger: %d %d ", *((int*)my), val);
    vfprintf(stdout, str, va);
}

static void term_func(void *my, int val, const char *str)

{
    printf("%s %d\n",  str, val);
    exit(3);
}

char *mstr = "No Memory";

//////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv)

{
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
    infile   = zalloc(MAX_PATH); if(infile == NULL) xerr2(mstr);
    outfile  = zalloc(MAX_PATH); if(outfile == NULL) xerr2(mstr);
    keyfile  = zalloc(MAX_PATH); if(keyfile == NULL) xerr2(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    //printf("Processed %d comline entries\n", nn);
    
    if(version)
        {
        printf("dibaencrypt version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
        
    if(verbose)
        {
        printf("infile='%s' outfile='%s' keyfile='%s'\n", infile, outfile, keyfile);
        }

    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("dibaencrypt: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
    }
    
    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], MAX_PATH);
        }
         
    //zverbose(1);
    gcry_error_t err;
    err = gcry_control(GCRYCTL_ENABLE_M_GUARD);
    if(err)
        {
        printerr(err, "guard");
        xerr2("Cannot set debug");
        }
    gcrypt_init();
    
    err = gcry_control(GCRYCTL_ENABLE_M_GUARD);
    if(err)
        {
        printerr(err, "guard");
        xerr2("Cannot set debug");
        }
    
    int  logval = 4;
    gcry_set_fatalerror_handler(term_func, &logval);
    gcry_set_log_handler(log_func, &logval);
    
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
            xerr2("dibakeygen: %s\n", err_str);
            }
        }
    
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
 
    err = gcry_control(GCRYCTL_DISABLE_SECMEM);
    
    FILE* lockf = fopen(keyfile, "rb");
    if (!lockf) {
        xerr2("dibadecrypt: Cannot open keyfile '%s'.", keyfile);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr2("dibadecrypt: Cannot allocate rsa buffer.");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr2("dibadecrypt: Cannot read public key.");
    }
    rsa_buf[rsa_len] = '\0';
    //printf("'%s'\n", rsa_buf);
    fclose(lockf);

    int declen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key(rsa_buf, &declen, &dec_err_str);
    if(mem == NULL)
        {
        xerr2("dibadecrypt: Cannot decode public key: '%s'.", dec_err_str);
        }
        
    if(ppub)
        dump_mem(mem, declen); 
        
    gcry_sexp_t pubkey;
    err = gcry_sexp_new(&pubkey, mem, declen, 1);
    zfree(mem);
    if (err) {
        //printerr(err, "encrypt");
        xerr2("dibadecrypt: Failed to read public key.");
        }
        
    if(ppub)
        print_sexp(pubkey);
    
    int keylen = gcry_pk_get_nbits(pubkey) / 8;
    //printf("keylen %d\n", keylen);
    
    char *buff2 = NULL;
    unsigned int plen2 = 0;
    gcry_sexp_t keyid = gcry_sexp_find_token(pubkey, "Key ID", 0);
    if(keyid == NULL)
        {
        xerr2("dibadecrypt: Public key has no keyid.");
        }
    //gcry_sexp_dump(pubkey);
        
    char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen2);
    // Menas test
    if(plen2 < 0)
        xerr2("dibadecrypt: Key length cannot be negative.");
    
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
            xerr2("dibadecrypt: Cannot allocate data for stdin.");
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
                xerr2("dibadecrypt: Out of preallocated stdin buffer. (%d bytes)\n", stdin_size);
            }
        //printf("Got stdin buffer %d bytes:\n'%s'\n", data_len, data_buf);
        }
    else if(strlen(infile))
        {
        FILE* dataf = fopen(infile, "rb");
        if (!dataf) {
            xerr2("dibadecrypt: Cannot open data file: '%s'", infile);
            }
        data_len = getfsize(dataf);
        //printf("data file size %d\n", rsa_len);
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(data_len + 1);
        if (!data_buf) {
            xerr2("dibadecrypt: Cannot allocate data buffer.");
            }
        if (fread(data_buf, data_len, 1, dataf) != 1) {
            xerr2("dibadecrypt: Cannot read data file '%s'.", infile);
            }
        }
    else
        {        
        xerr2("dibadecrypt: No data specified for encryption");
        }
    
    char pub_hash[32];
    int  outlen = 0;
    int  outlim = data_len * 2 + keylen * 2 + plen2 + 
                        sizeof(int) + 1 + sizeof(pub_hash);
    zline2(__LINE__, __FILE__);
    char *outptr = zalloc(outlim);
    if(!outptr)
        {
        xerr2("dibadecrypt: Cannot allocate memory.");
        }
    
    // Hash the original message first     
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash, 
                    (const void*) data_buf, data_len);
     
    //dump_mem(pub_hash, sizeof(pub_hash));
       
    // Start with the hash
    *( (short *)(outptr+outlen)) = (short) sizeof(pub_hash);
    outlen += sizeof(short); 
    memcpy(outptr+outlen, pub_hash, sizeof(pub_hash));
    outlen += sizeof(pub_hash); 
    
    // Add the key id and hash
    //
    // short  int    varlen
    // Len +  rand + hash
    //       |-----------| => encrypt from rand to end of keyid
    
    *( (short *)(outptr+outlen)) = (short) (plen2 & 0xffff) + sizeof(int);
    outlen += sizeof(short); 
    gcry_randomize(outptr + outlen, sizeof(int), GCRY_STRONG_RANDOM);
    outlen += sizeof(int); 
    memcpy(outptr + outlen, buff2, plen2); 
    outlen += plen2;
    
    #if 0
    // Encrypt in place
    gcry_cipher_hd_t aes_hd2; 
    get_twofish_ctx(&aes_hd2, keypass, strlen(keypass));
    err = gcry_cipher_encrypt(aes_hd2, (unsigned char*) outptr + sizeof(short),
                              plen2 + sizeof(int), NULL, 0);
    if (err) {
        xerr2("dibadecrypt: Failed to encrypt key id.");
        }
    gcry_cipher_close(aes_hd2);
    #endif
    
    zfree(buff2);
                
    // Create the message. 
    // Parse keylen - sizeof(int) chunks, add 4 bytes of random 
    // Padd last chunk with zeros (done by the algo)
    
    int blocklen = keylen -  4 * sizeof(int);  
    
    zline2(__LINE__, __FILE__);
    char *tmp_buf = zalloc(keylen + 4 * sizeof(int));
    for(int loop = 0; loop < data_len; loop += blocklen)
        {
        int curr_len = blocklen;
        if(data_len - loop < blocklen)
            {
            curr_len = data_len - loop;
            }
        gcry_randomize(tmp_buf, sizeof(int), GCRY_STRONG_RANDOM);
        
        // THIS WAS A WHOLE DAY OF CODING. 
        // Mark the buffer non 7 bit clean, so the copy routine will 
        // not switch to ascii (arbitrary const)
        tmp_buf[0] = 0xee;
        memcpy(tmp_buf + sizeof(int), data_buf + loop, curr_len);
        
        gcry_sexp_t ciph, enc_data;
        
#ifndef TEST_PK
        /* Encrypt the message. */
        gcry_mpi_t msg;
        int scanned;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, tmp_buf,
                            curr_len + sizeof(int), &scanned);
        if (err) {
            xerr2("dibadecrypt: Failed to create a mpi from the message.");
            }
        //printf("mpi scanned %d\n", scanned);
        err = gcry_sexp_build(&enc_data, NULL,
                               "(data (flags raw) (value %m))", msg);
        if (err) {
            //printerr(err, "bulding sexp");
            xerr2("dibadecrypt: Failed to create a sexp from the message.");
        }
        gcry_mpi_release(msg);
        err = gcry_pk_encrypt(&ciph, enc_data, pubkey);
        gcry_sexp_release(enc_data);
#else   
        // This is a NULL encryption, testing ONLY
        err = gcry_sexp_build(&ciph, NULL,
                "(enc-val (rsa (a %b)))", curr_len + sizeof(int), tmp_buf );
#endif   
        if (err) {
            //printerr(err, "encryption");
            xerr2("dibadecrypt: Encryption failed.");
        }
        //print_sexp(ciph);
        gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
        if(ddd == NULL)
        if (err) {
            xerr2("dibadecrypt: find token in encrypted result failed");
            }
        unsigned int plen = 0;
        char *dptr = (char *)gcry_sexp_nth_data(ddd, 1, &plen);
        
        if(dump)
            {
            dump_mem(dptr, plen);
            }
            
        // Add to our cummulative buffer
        if(outlen + plen > outlim)
            {
            xerr2("dibadecrypt: Could not write all mem to buffer.");
            }
        *( (short *)(outptr + outlen)) = (short) (plen & 0xffff);
        outlen += sizeof(short); 
        memcpy(outptr + outlen, dptr, plen); 
        outlen += plen;
        
        gcry_sexp_release(ciph);
        }
        
    zfree(tmp_buf);    
    //print_mem(outptr, outlen);
        
    #ifndef TEST_BLUE
    int bret = bluepoint2_encrypt(outptr, outlen, keypass, strlen(keypass));
    #endif
    int outx, plen3;
    char *mem3 = base_and_lim(outptr, outlen, &outx);
    
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr2("dibadecrypt: Cannnot create outfile '%s'.", outfile);
            }
        }
    int fullen =  strlen(cyph_start) + strlen(cyph_end) + outx + 10;
    zline2(__LINE__, __FILE__);
    char *mem4 = zalloc(fullen);
    if(!mem4) 
        xerr2("dibadecrypt: Cannot allocate memory for output.");
    
    int add = snprintf(mem4, fullen, "%s\n", cyph_start);
    // Big no no. Will terminate at the first null (random error introduced)
    //add += snprintf(mem4 + add, fullen - add, "%.*s\n", outx, mem3);
    memcpy(mem4 + add, mem3, outx);  add += outx;
    add += snprintf(mem4 + add, fullen - add, "%s\n", cyph_end);
    //print_mem(mem4, add);
    int retf = fwrite(mem4, add, 1, outf); 
    //fflush(outf);
    if(retf != 1)
        {
        xerr2("dibadecrypt: Cannot write to output file '%s'.", outfile);
        }
    zfree(mem4);
    if(outf != stdout)
        {
        fclose(outf);
        }
    zfree(mem3);
    zfree(data_buf);
    
    /* Release contexts. */
    gcry_sexp_release(pubkey);
    
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);  zfree(outptr);
    zline2(__LINE__, __FILE__);
    zfree(infile); zfree(outfile); 
    zline2(__LINE__, __FILE__);
    zfree(keyfile);  zfree(dummy);
    zleak();
    
    //gcry_control(GCRYCTL_DUMP_RANDOM_STATS);
    //gcry_control(GCRYCTL_DUMP_MEMORY_STATS);
    
    return 0;
}

/* EOF */





