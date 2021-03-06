// -------------------------------------------------------------------------
// Bluepoint encryption routines.
//
//   How it works:
//
//     Strings are walked char by char with the loop:
//
//    for (loop = 0; loop < slen; loop++)
//        {
//        aa = str[loop];
//        }
//
//    In other languages:
//         {
//         $aa = ord(substr($_[0], $loop, 1));
//         do something with $aa
//         substr($_[0], $loop, 1) = pack("c", $aa);
//         }
//
//   Flow:
//         generate vector
//         generate pass
//         walk forward with password cycling loop
//         walk backwards with feedback encryption
//         walk forward with feedback encryption
//
//  The process guarantees that a single bit change in the original text
//  will change every byte in the resulting block.
//
//  The bit propagation is such a high quality, that it beats current
//  industrial strength encryptions.
//
//  Please see bit distribution study.
//
// -------------------------------------------------------------------------
//
// How to use:
//
//  bluepoint_encrypt($orig, $pass);                -- encrypted in place
//  bluepoint_decrypt($cypher, $pass);              -- decrypted in place
//  $hash       = bluepoint_hash($orig, $pass);
//  $crypthash  = bluepoint_crypthash($orig, $pass);
//
// The reference implementation for version 1.0 contains a (default) sample
// clear text and a sample cypher text.
// Porting is correct if the new cypher text is a duplicate of the following:
//
// orignal='abcdefghijklmnopqrstuvwxyz' pass='1234'
// ENCRYPTED:
// -2b-e4-5c-46-75-9e-05-c3-74-d4-35-76-5b-84-10-f8-b7-7e-f4-07-0a-37-50-07-69-3d
// END ENCRYPTED
// decrypted='abcdefghijklmnopqrstuvwxyz'
// HASH:
// -754656719 0xd304da31
// CRYPTHASH:
// -1382909316 0xad927a7c
//
///////////////////////////////////////////////////////////////////////////
// At this point PERL and C implementations exist, here is a session dump:
//
// ant:/srv/www/archive/bluepoint/bluepoint3 # make; ./test_blue
// make: `test_blue' is up to date.
// orignal='abcdefghijklmnopqrstuvwxyz' pass='1234'
// ENCRYPTED:
// -2b-e4-5c-46-75-9e-05-c3-74-d4-35-76-5b-84-10-f8-b7-7e-f4-07-0a-37-50-07-69-3d
// END ENCRYPTED
// decrypted='abcdefghijklmnopqrstuvwxyz'
// HASH:
// -754656719 0xd304da31
// CRYPTHASH:
// -1382909316 0xad927a7c
//
// ant:/srv/www/archive/bluepoint/bluepoint3 # perl test_blue.pl
// original='abcdefghijklmnopqrstuvwxyz'  pass='1234'
// ENCRYPTED:
// -2b-e4-5c-46-75-9e-05-c3-74-d4-35-76-5b-84-10-f8-b7-7e-f4-07-0a-37-50-07-69-3d
// END ENCRYPTED
// decrypted='abcdefghijklmnopqrstuvwxyz'
// HASH:
// -754656719  0xd304da31
// CryptHASH:
// -1382909316  0xad927a7c
//
///////////////////////////////////////////////////////////////////////////

#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#define DEF_DUMPHEX  1   // undefine this if you do not want bluepoint_dumphex

///////////////////////////////////////////////////////////////////////////
// The following defines are used to test multi platform steps.
// These will generate a cypher text incompatible with other implementations
// FOR TESTING ONLY

//define NOROTATE        1   // uncomment this if you want no rotation
//define NOPASSCRYPT     1   // uncomment this if you want no pass crypt

#include "bluepoint.h"

#define     ROTATE_LONG_RIGHT(x, n) (((x) >> (n))  | ((x) << (32 - (n))))
#define     ROTATE_LONG_LEFT(x, n) (((x) << (n))  | ((x) >> (32 - (n))))

#define     ROTATE_CHAR_RIGHT(x, n) (((x) >> (n))  | ((x) << (8 - (n))))
#define     ROTATE_CHAR_LEFT(x, n) (((x) << (n))  | ((x) >> (8 - (n))))

static  void    do_encrypt(char *str, int slen, char *pass, int plen);
static  void    do_decrypt(char *str, int slen, char *pass, int plen);
static  void    prep_pass(char *pass, int plen, char *newpass);

//# -------------------------------------------------------------------------
//# These vars can be set to make a custom encryption:

char vector[]  = "crypt";              //# influence encryption algorythm
int passlim    = 32;                   //# maximum key length (bytes)

char    forward    = 0x55;             //# Constant propagated on forward pass
char    backward   = 0x5a;             //# Constant propagated on backward pass
char    addend     = 17;               //# Constant used adding to encrypted values

//# -------------------------------------------------------------------------
//# These vars can be set show op details

int verbose    = 0;                    //# Specify this to show working details
int functrace  = 0;                    //# Specify this to show function args

//# -------------------------------------------------------------------------
//# Use: encrypt($str, $password);

void    bluepoint_encrypt(char *buff, int blen, char *pass, int plen)

{
    char newpass[2 * passlim];

    if(plen == 0 || blen == 0)
        {
        return;
        }

   if(functrace)
       {
       printf("bluepoint_encrypt\nbuff=%s\n", bluepoint_dumphex(buff, blen));
       printf("pass=%s\n", bluepoint_dumphex(pass, plen) );
       }

    prep_pass(pass, plen, newpass);

    do_encrypt(buff, blen, newpass, passlim);
}

//# -------------------------------------------------------------------------
//# Use: bluepoint_decrypt($str, $password);

void    bluepoint_decrypt(char *buff, int blen, char *pass, int plen)

{
    char newpass[2 * passlim];

    if(plen == 0 || blen == 0)
        {
        return;
        }

    if(functrace)
        {
        printf("bluepoint_decrypt()\nbuff=%s\n", bluepoint_dumphex(buff, blen));
        printf("pass=%s\n", bluepoint_dumphex(pass, plen) );
        }

    prep_pass(pass, plen, newpass);

    do_decrypt(buff, blen, newpass, passlim);
}

///////////////////////////////////////////////////////////////////////////
// Prepare pass

void    prep_pass(char *pass, int plen, char *newpass)

{
    int loop;
    char vec2[passlim];

    // Duplicate vector
    int vlen = strlen(vector);
    strcpy(vec2, vector);
    newpass[0] = 0;

    for(loop = 0; loop < passlim / plen + 1; loop++)
        {
        strcat(newpass, pass);
        strcat(newpass, "_");
        }

    newpass[passlim] = 0;

    if(verbose)
        printf("prep_pass() newpass: %s\n", newpass);

#ifndef NOPASSCRYPT
    do_encrypt(vec2, vlen, vector, vlen);
#endif

    if(verbose)
        {
        printf("prep_pass() eVEC: ");
        bluepoint_dumphex(vec2, vlen);
        printf("\n");
        }

#ifndef NOPASSCRYPT
    do_encrypt(newpass, passlim, vec2, vlen);
#endif

}

//# -------------------------------------------------------------------------
//# Hash:
//# use: hashvalue = hash($str)
//#
//# Implementing the following 'C' code
//#
//#   ret_val ^= (unsigned long)*name;
//#   ret_val  = ROTATE_LONG_RIGHT(ret_val, 10);          /* rotate right */sub hash
//#

ulong   bluepoint_hash(char *buff, int blen)

{
    unsigned long    sum = 0;
    int     loop;
    char    aa, aa2, aa3;

    for (loop = 0; loop < blen; loop++)
        {
        sum ^= (unsigned char)buff[loop];
        sum = ROTATE_LONG_RIGHT(sum, 10);          /* rotate right */
        }

    return sum;
}

//# -------------------------------------------------------------------------
//# Crypt and hash:
//# use: crypthash = bluepoint_crypthash($str, "pass")

ulong   bluepoint_crypthash(char *buff, int blen, char *pass, int plen)

{
    unsigned long    sum = 0;

    // Duplicate buffer
    char *duplicate = (char *)malloc(blen + 4);
    if(!duplicate)
        {
        return(0L);
        }
    memcpy(duplicate, buff, blen);

    bluepoint_encrypt(duplicate, blen, pass, plen);
    sum = bluepoint_hash(duplicate, blen);

    free(duplicate);
    return(sum);
}

//# -------------------------------------------------------------------------
//# The following routines are internal to this module:

void    do_encrypt(char *str, int slen, char *pass, int plen)

{
    int loop, loop2 = 0;
    unsigned char   aa, bb;;

    if(verbose)
        {
        printf( "encrypt str='%s' len=%d pass='%s' plen=%d\n",
                 str, slen, pass, plen);
        }

    //# Pass loop  (encrypt)
    for (loop = 0; loop < slen; loop++)
        {
        aa = str[loop];

        aa = aa ^ pass[loop2];

        loop2++;
        if(loop2 >= plen) {loop2 = 0;}     //#wrap over

        str[loop] = aa;
        }

    //# Backward loop (encrypt)
    bb = 0;
    for (loop = slen-1; loop >= 0; loop--)
        {
        aa = str[loop];

        aa ^= backward;
        aa += addend;
        aa += bb;

        bb = aa;

        str[loop] = aa;
        }

    //# Forward loop  (encrypt)
    bb = 0;
    for (loop = 0; loop < slen; loop++)
        {
        aa = str[loop];

        aa ^= forward;
        aa  += addend;
        aa  += bb;

        #ifndef NOROTATE
        aa = ROTATE_CHAR_RIGHT(aa, 3);
        #endif

        bb = aa;

        str[loop] = aa;
        }
}

//# -------------------------------------------------------------------------
//# Internal to this module:

void    do_decrypt(char *str, int slen, char *pass, int plen)

{
    int loop, loop2 = 0;
    unsigned char  aa, bb, cc;

    if(verbose)
        {
        printf( "decrypt(inp) str=%s len=%d pass=%s plen=%d\n",
                  str, slen, pass, plen);
        }

    //# Forward loop (decrypt)
    cc = 0;
    for (loop = 0; loop < slen; loop++)
        {
        bb = cc;

        cc = aa = str[loop];

        #ifndef NOROTATE
        aa = ROTATE_CHAR_LEFT(aa, 3);
        #endif

        aa -=  bb;
        aa -= addend;

        aa ^= forward;

        str[loop] = aa;
        }

    //# Backward loop  (decrypt)
    cc = 0;
    for (loop = slen-1; loop >= 0; loop--)
        {
        bb = cc;
        aa = cc = str[loop];

        aa -= bb;
        aa -= addend;
        aa ^= backward;

        str[loop] = aa;
        }

    //# Pass loop   (decrypt)
    for (loop = 0; loop < slen; loop++)
        {
        aa = str[loop];

        aa = aa ^ pass[loop2];

        loop2++; if(loop2 >= plen) {loop2 = 0;}     //#wrap over

        str[loop] = aa;
        }
}

//# -------------------------------------------------------------------------
// use it for testing only as it has a 256 byte buffer limit
//# Use: mystr = bluepoint_dumphex($str)

#ifdef DEF_DUMPHEX

char buff[2056];

char    *bluepoint_dumphex(char *str, int len)

{
    buff[0] = 0;  int loop = 0, pos = 0;
    
    if(verbose)
        {
        printf("bluepoint_dumphex str=%p len=%d ", str, len);
        }
    
    for (loop = 0; loop < len; loop++)
        {
        pos += sprintf(buff + pos, "-%02x", ( unsigned char)str[loop]);
        
        if(pos >= (sizeof(buff) - 8))
            {
            //# Show that string is incomplete
            buff[pos++] = ' ';
            buff[pos++] = '.';
            buff[pos++] = '.';
            buff[pos++] = '.';
            break;
            }
        }
    buff[pos] = '\0';
    return(buff);
}

#endif



