# Makefile for console digibank client
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

# GCC will error check better than cl, use for build test
CC=gcc
COMPILE=bash compile.sh

# However, one can proceed with the windows free tools as well
#CC=cl
#COMPILE=cmd /c compile.bat

# The following block locates all dependencies

TOOLDIR=../tools
BLUEDIR=../bluepoint
COMMON=../common

INC2=../../libgcrypt/libgpg-error-1.27/src 
INC3=../../libgcrypt/libgcrypt-1.7.8/src 
INC4=$(BLUEDIR)
INC5=$(TOOLDIR)
INC6=$(COMMON)

LIB2=../../libgcrypt/libgcrypt-1.7.8/src/.libs/ 
LIB3=../../libgcrypt/libgpg-error-1.27/src/.libs/
LIB4= -l gcrypt -l gpg-error 

OPT2= -I $(INC2) -I $(INC3) -I $(INC4) -I $(INC5) -I $(INC6) -I .. 
OPT3= -L $(LIB2) -L $(LIB3)  $(LIB4)

# ----------------------------------------------------------------------------------

ENCFILE = $(BLUEDIR)/bluepoint3.c $(TOOLDIR)/cmdline.c $(TOOLDIR)/misc.c \
            $(TOOLDIR)/zmalloc.c $(TOOLDIR)/base64.c  $(TOOLDIR)/gcry.c  \
                $(TOOLDIR)/gsexp.c $(TOOLDIR)/zstr.c  $(COMMON)/dibastr.c \
                    $(COMMON)/dibautils.c
                
# Included in dependencies, as they change over time
HEADERS = $(BLUEDIR)/bluepoint3.h $(COMMON)/diba.h

all:   dibapow.exe dibachain.exe dibanull.exe
    
dibapow.exe:  dibapow.c  $(ENCFILE)  $(HEADERS)
	$(CC) $(OPT2) dibapow.c $(ENCFILE)  $(OPT3)  -o dibapow.exe

dibachain.exe:  dibachain.c  $(ENCFILE) $(HEADERS)
	$(CC) $(OPT2)  dibachain.c $(ENCFILE) $(OPT3) -o dibachain.exe

test: tests

tests:
	@echo "No tests here"

clean:
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe

cleandata:
	rm -rf data

testdata: cleandata
	dibapow.exe -n
	dibapow.exe ./data/000000000000.bce payload















