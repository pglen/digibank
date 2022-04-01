# Makefile for console digibank client
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

# GCC will error check better than cl, use for build test
#CC=gcc
#COMPILE=bash compile.sh

# However, one can proceed with the windows free tools as well
CC=cl
OPT=/nologo 
COMPILE=cmd /c compile.bat

# ----------------------------------------------------------------------------------

HEADERS=bluepoint2.h diba.h

all:    digibank.exe dibagen.exe dibadec.exe dibapow.exe

test:   test_blue2.c block_blue2.c  dibautils.c $(HEADERS)
	$(CC) $(OPT) test_blue2.c bluepoint2.c  dibautils.c
	$(CC) $(OPT) block_blue2.c bluepoint2.c  dibautils.c

digibank.exe:  digibank.c bluepoint2.c  dibautils.c $(HEADERS)
	$(CC) $(OPT) digibank.c bluepoint2.c  dibautils.c

dibagen.exe:  dibagen.c bluepoint2.c   dibautils.c $(HEADERS)
	$(CC) $(OPT) dibagen.c bluepoint2.c  dibautils.c

dibadec.exe:  dibadec.c bluepoint2.c   dibautils.c $(HEADERS)
	$(CC) $(OPT) dibadec.c bluepoint2.c  dibautils.c

dibapow.exe:  dibapow.c bluepoint2.c   dibautils.c $(HEADERS)
	$(CC) $(OPT) dibapow.c bluepoint2.c  dibautils.c

clean:
	-@rm -f *.o *.obj
	-@rm -f a.out











