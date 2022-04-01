
/* =====[ zmalloc.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba 
                    [Digital Bank]. Testing libgcrypt library.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmalloc.h"

#define POOLSIZE 64

// Cheater malloc. Decorate as follows:
// xxxx 'a' 'b' mmmmmmm 'c' 'd'
// xxxx is 4 bytes of length, mmmmmm is the requested memory

static void *zarr[POOLSIZE] = {(void*)0};
static int  zlinearr[POOLSIZE] = {1};

static int zlast = 0;
static int zlastline = 0;
static int check_on = (1==1);
static int verbose_on = (1==0);

static void die()
{
    printf("Cannot allocate memory, error exit\n");
    exit(2);
}

void zline(int line)
{
   zlastline = line;
}

void zcheck(void *mem, int line)

{
    if(!check_on)
        return;
    
    char *mem2 = (char *)mem;
    int  *mem3 = (int  *)mem;
    char *mem4 = (char *)mem;
    
    mem2 -= 4;
    mem3 = (int *)(mem2 - sizeof(int));
    mem4 += *mem3; 
    
    //printf("%p %d '%c %c %c %c' '%c %c %c %c' \n", mem, *mem3, mem2[0], mem2[1],  mem2[2],  mem2[3],
    //                    mem4[0], mem4[1], mem4[2], mem4[3] );
                        
    if(mem2[0] != 'a' ||  mem2[1] != 'b' ||
             mem2[2] != 'c' ||  mem2[3] != 'd')
         {
         printf("Memory check failed. (at beginning) Line: %d\n", line);
         }
    if(mem4[0] != 'e' ||  mem4[1] != 'f' ||
             mem4[2] != 'g' ||  mem4[3] != 'h')
         {
         printf("Memory check failed. (at end) Line: %d\n", line);
         }
}

void *zalloc(int msize)

{
    char *mem2 = NULL; int  *mem3 = NULL;
    void *mem = malloc (msize + 8 + sizeof(int));
    
    if (mem == NULL)
        return NULL;
        //die();
        
    if(zlinearr[0] == 1)
        {
        memset(zarr, 0, sizeof(zarr)); 
        memset(zlinearr, 0, sizeof(zlinearr)); 
        }
    memset(mem, 0, msize);
    mem2 = (char*)mem;
    mem3 = (int*)mem;
    
    *(mem3) = msize;
    
    *(mem2 + 4) = 'a';
    *(mem2 + 5) = 'b';
    *(mem2 + 6) = 'c';
    *(mem2 + 7) = 'd';
    
    *(mem2 + 4 + msize + sizeof(int) + 0) = 'e';
    *(mem2 + 4 + msize + sizeof(int) + 1) = 'f';
    *(mem2 + 4 + msize + sizeof(int) + 2) = 'g';
    *(mem2 + 4 + msize + sizeof(int) + 3) = 'h';
    
    //printf("%c %c %c %c \n", mem2[4], mem2[5],
    //            *(mem2 + msize + sizeof(int)), *(mem2 + msize + sizeof(int)+1) );
   
    void *ret = (void *) (mem2 + 4 + sizeof(int)); 
    zcheck(ret, zlastline );
    
    if(verbose_on)
        printf("Alloc at line %d (0x%p)\n", zlastline, ret);
    if(zlast < POOLSIZE)
        {
        zarr[zlast] = ret;
        zlinearr[zlast] =  zlastline;
        zlast++;
        }
    else 
        {              
        // Find deleted slot
        int loop;
        for(loop = 0; loop < zlast; loop++)
            {
            //printf("Finding slot\n");
            if(zarr[loop] == (void*)0)
                {   
                zarr[loop] = ret;
                zlinearr[loop] =  zlastline;
                break;
                }
            }
        if(loop == zlast)
            printf("Increase zlast memory pool\n");
        }
        
    //for(int loop = 0; loop < zlast; loop++)
    //    printf("Dump %d (0x%p)\n", zlinearr[loop], zarr[loop]); 
            
    return ret;
}

void zfree(void *mem)

{
    zfree2(mem, zlastline);
}

void zfree2(void *mem, int line)

{
    if(verbose_on)
        printf("Free at line %d (0x%p)\n", line, mem);
        
    int was = 0;
    for(int loop = 0; loop < zlast; loop++)
        {
        //printf("Dump2 %d (0x%p)\n", zlinearr[loop], zarr[loop]); 
        if(zarr[loop] == mem)
            {
            //printf("unhook %p\n", zarr[loop]);
            zarr[loop] = NULL;
            zlinearr[loop] = 0;
            was = 1;
            }
        }
        
    if(was == 0)
        {
        printf("Trying to free unallocated memory at line %d (0x%p)\n",
                zlastline, mem);
        return;
        } 
          
    zcheck(mem, line);
    char *mem2 = (char *)mem; 
    mem2 -= 4 + sizeof(int);
    
    free( (void *)mem2 );
}

void zleak()
{
    for(int loop = 0; loop < zlast; loop++)
        if(zarr[loop] != NULL)
            printf("Leak at line %d (0x%p)\n", zlinearr[loop], zarr[loop]); 
    
}




