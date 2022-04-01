# Makefile for console digibank client
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

# GCC will error check better than cl, use for build test
CC=gcc
OPT=-I bluepoint
COMPILE=bash compile.sh

# However, one can proceed with the windows free tools as well
#CC=cl
#OPT=/nologo 
#COMPILE=cmd /c compile.bat

# ----------------------------------------------------------------------------------

HEADERS=bluepoint/bluepoint2.h diba.h

all:    digibank.exe dibagen.exe dibadec.exe dibapow.exe

test:   test_blue2.c block_blue2.c  dibautils.c $(HEADERS)
	$(CC) $(OPT) test_blue2.c bluepoint/bluepoint2.c  dibautils.c
	$(CC) $(OPT) block_blue2.c bluepoint/bluepoint2.c  dibautils.c

digibank.exe:  digibank.c bluepoint/bluepoint2.c  dibautils.c $(HEADERS)
	$(CC) $(OPT) -o digibank.exe digibank.c bluepoint/bluepoint2.c  dibautils.c

dibagen.exe:  dibagen.c bluepoint/bluepoint2.c   dibautils.c $(HEADERS)
	$(CC) $(OPT) -o dibagen.exe dibagen.c bluepoint/bluepoint2.c  dibautils.c

dibadec.exe:  dibadec.c bluepoint/bluepoint2.c   dibautils.c $(HEADERS)
	$(CC) $(OPT) -o dibadec.exe dibadec.c bluepoint/bluepoint2.c  dibautils.c

dibapow.exe:  dibapow.c bluepoint/bluepoint2.c  dibautils.c $(HEADERS)
	$(CC) $(OPT) -o dibapow.exe dibapow.c bluepoint/bluepoint2.c  dibautils.c

clean:
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe












