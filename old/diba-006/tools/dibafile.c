
/* =====[ dibafile.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank]. File format code.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
     0.00  nov.05.2017     Peter Glen      Initial version.
 
   ======================================================================= */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "misc.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "dibafile.h"

#include "zlib.h"

unsigned int calc_buffer_sum(const char *ptr, int len)

{
    unsigned int ret = 0;
    //printf("calc_buffer_sum %p %d\n", ptr, len);
    for(int loop = 0; loop < len; loop++)
        {
        ret += (unsigned char)ptr[loop];
        ret = (ret << 3) | ret >> 21;
        }
    //printf("sum ret = %x\n", ret);
    return ret;   
}

///////////////////////////////////////////////////////////////////////////
// Return TRUE if OK, fill in err_str if not

FILE    *OpenDibaFile(const char *lpszPathName, char **err_str)

{
    //printf("Opening Diba file: %s\n", lpszPathName);
    FILE *Diba = NULL;  *err_str = NULL;
    if(!lpszPathName)
        {
        *err_str = "Cannot open NULL"; return Diba;
        }
    if(access(lpszPathName, F_OK) < 0)
        {
        *err_str = "File does not exist."; return Diba;
        }
    Diba = fopen(lpszPathName, "rb");
    if (!Diba)
        {
        *err_str = "Cannot open Diba file.";
        //printf("Cannot open Diba file\n", lpszPathName);
        return Diba;
        }
    return Diba;
}

//////////////////////////////////////////////////////////////////////////
// Start reading Diba file from the beginning

void    RewindDibaFile(FILE *Diba)

{
    fseek(Diba, 0, SEEK_SET);                                             
}

//////////////////////////////////////////////////////////////////////////
// Return the next diba key, 
// FILE is positioned at the beginning of value

char*   FindNextDibaKey(FILE *Diba, int *len, char **err_str)

{
    char* buff = NULL; *err_str = NULL; *len = 0;
    
    while(1==1)
        {
        int slen, stype, ssum;
        
        if(GetDibaSection(Diba, &slen, &stype, &ssum) < MINCHSIZE)
            {
            *err_str = "End of file.";
            return(buff);
            }
        if(*len < 0)
            {
            *err_str = "Unexpected length.";
            return(buff);
            }
        // Is it a key?
        if(stype & 0x80)
            {
            zline2(__LINE__, __FILE__);
            buff =  zalloc(slen + 1);
            if(!buff)
                {
                *err_str = "Cannot allocate memory.";
                return(buff);
                }
            int ret = fread(buff, 1, slen, Diba);
            //printf("read %d\n", ret);
            buff[slen] = '\0';
            *len = slen;
            break;
            }    
        // Skip this chunk, get next
        fseek(Diba, slen, SEEK_CUR);
        }
    return(buff);
}
             
//////////////////////////////////////////////////////////////////////////                                                                                   
// Get key / value pair, fill into structure
 
int   GetDibaKeyVal(FILE *Diba, chunk_keypair *ptr, char **err_str)

{
    int ret = 0, len; char* buff = NULL;
    *err_str = NULL; 
    
    // Init them
    ptr->key = ptr->val = NULL;  ptr->klen = ptr->vlen = 0;
    
    buff = FindNextDibaKey(Diba, &len, err_str);
    if(!buff)
        {
        return ret; 
        }
    int len2, type2;     
    char* buff2 = GetNextDibaChunk(Diba, &len2, &type2, err_str);
    if(!buff2)
        {
        return ret; 
        }  
    // All working, fill in structure
    ptr->key = buff;    ptr->klen = len;
    ptr->val = buff2;   ptr->vlen = len2;
    ret = 1;
    return ret;    
}

//////////////////////////////////////////////////////////////////////////
// Put key / val pair to file

int   PutDibaKeyVal(FILE *Diba, chunk_keypair *ptr, char **err_str)

{
    //printf("key=%s %d val=%s %d\n", 
    //                    ptr->key, ptr->klen, ptr->val, ptr->vlen);
    PutDibaSection(Diba, ptr->key, ptr->klen, CHUNK_TEXT | CHUNK_KEY);
    PutDibaSection(Diba, ptr->val, ptr->vlen, CHUNK_TEXT);
    return(1);
}

//////////////////////////////////////////////////////////////////////////
// 

char*   GetNextDibaChunk(FILE *Diba, int *len, int *type, char **err_str)
        
{       
    char *buff = NULL;         
    *err_str = NULL; *len = 0; *type = 0;
    int   sum = 0;
    
    if(GetDibaSection(Diba, len, type, &sum) < MINCHSIZE)
        {
        *err_str = "End of file.";
        return(buff);
        }
    if(*len < 0)
        {
        *err_str = "Unexpected length.";
        return(buff);
        }
    zline2(__LINE__, __FILE__);
    buff =  zalloc(*len + 1);
    if(!buff)
        {
        *err_str = "Cannot allocate memory.";
        return(buff);
        }
    int ret = fread(buff, 1, *len, Diba);
    //printf("read %d\n", ret);
    //buff[*len] = '\0';
     if(*type & CHUNK_ZIPPED)
        {
        unsigned long  ucomprLen;
        int err; char *mem; 
        for(int loop = 1; loop < 10; loop++)
            {
            //printf("unZipping stage %d ... \n", loop);
            ucomprLen  = loop * 4 * (*len); 
            mem = zalloc(ucomprLen + 1);
            int err = uncompress(mem, &ucomprLen, (const Bytef*)buff, *len);
            if(err != Z_BUF_ERROR)
                break;
            zfree(mem);
            }
        if(err != Z_OK)
            {
            //printf("un ratio %d %d %f\n", ucomprLen, *len, 
            //                            (float)(ucomprLen)/(*len));
            *len = ucomprLen; 
            zfree(buff);
            buff = mem;
            }
        else
            {
            //printf("Error on unzip %d\n", err);
            zfree(mem);
            }
     // Check SUM      
    unsigned int org = calc_buffer_sum(buff, *len);
    //printf("sum %x org %x\n", sum, org);
    if(sum != org)
        {
        // Force kill data
        *err_str = "Bad checksum on chunk.";
        zfree(buff);
        return(NULL);
        }
    }
   //printf("GetNextDibaChunk: '%s'\n", buff);
    return buff;
}

///////////////////////////////////////////////////////////////////////////

FILE    *CreateDibaFile(const char *fname, char **err_str)

{
    char header[MAX_PATH];
    *err_str = NULL;
    
    //printf("Save Diba file %s\n", fname);
    FILE *myFile = fopen(fname, "wb");
    if(!myFile) 
        {
        *err_str = "Cannot create Diba file";
        return myFile;
        }
    snprintf(header, MAX_PATH, FILE_HEADER_STR, 1, 1);
    PutDibaSection(myFile, header, strlen(header), CHUNK_HEADER);
    
    return myFile;
}

// Write out final chunk and close file

int     CloseDibaFile(FILE *fp, int writefinal)

{
    if(writefinal)
        {
        char footer[MAX_PATH];
        snprintf(footer, MAX_PATH, "%s", "End of Diba File.\n");
        PutDibaSection(fp, footer, strlen(footer), CHUNK_FOOTER);
        }
    fclose(fp);
    return 1;
}
                               
////////////////////////////////////////////////////////////////
// Return number of bytes read, negative on error
//

int     GetDibaSection(FILE *ff, int *len, int *type, int *sum)

{
    // Surround string with zeros, so debug print is ok
    char  trail  = 0, buff[CHUNKSIZE + 1], trail2 = 0;
    
    // Assure defaults
    *len = *type = *sum = 0;
    
    int ret = fread(buff, 1, CHUNKSIZE, ff);
    if(ret <= 0)
        {
        //printf("Stream ended before file\n");
        return ret;
        }
    if(ret >  CHUNKSIZE)
        {
        //printf("Unexpected read return value\n");
        return ret;
        }
    buff[ret] = '\0';
    
    //printf("Got buffer '%s' \n", buff);
    if(buff[0] != 'D' || buff[1] != 'I')
        {
        // TODO Mark the buffer tainted ... 
        //*err_str = ("Invalid Section. Skipping ....");
        //printf("Invalid Section. Skipping ....");
        }
    char *end = strchr(buff, '\n');
    if (end)
        {
        // Go back to end of real input
        int num = end - buff;     
        fseek(ff, -(CHUNKSIZE - 1 - num), SEEK_CUR);
        }
        
    int ret2 = sscanf(buff, CHUNK_HEADER_STR, type, len, sum);
    //printf("getdibasection: ret2=%d type=%x len=%x sum %x \n\n", 
    //                            ret2, *type, *len, *sum);
    
    return(ret);
}

////////////////////////////////////////////////////////////////
// Return payload size written, negative on error

int     PutDibaSection(FILE *ff, const char *ptr, int len, int type)

{
    char tmp[MAX_PATH];    int ret = 0;
    unsigned int sum = calc_buffer_sum(ptr, len);
    char *mem = NULL;
    
    if(type & CHUNK_ZIPPED)
        {
        unsigned long  comprLen = len;
        //printf("Zipping ... \n '%s'\n", ptr);
        mem = zalloc(comprLen + 1);
        int err = compress(mem, &comprLen, (const Bytef*)ptr, len);
        if(!err)
            {
            //printf("Zipped ... \n '%s'\n", mem);
            //printf("ratio %d %d %f\n", comprLen, len, (float)(comprLen)/len);
            len = comprLen; ptr = mem;
            }
        else
            {
            // Just store it ...
            type = type & (~CHUNK_ZIPPED);
            }
        }
    snprintf(tmp, MAX_PATH, CHUNK_HEADER_STR, type, len, sum);
    ret = fwrite(tmp, 1, strlen(tmp), ff);
    if(ret < 0) return ret;
    ret = fwrite(ptr, 1, len, ff);
    if(type & CHUNK_ZIPPED)
        {
        zfree(mem);   
        }
    return(ret);
}

/* EOF */
