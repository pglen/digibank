# These point to already built sub parts. Edit it if you move
# the files to a different directory.
# This is so one can use the parts without installation.

#../../libgcrypt/libgcrypt-1.7.8/

INC2=../../libgcrypt/libgpg-error-1.27/src 
INC3=../../libgcrypt/libgcrypt-1.7.8/src 
INC4=../bluepoint
LIB2=../../libgcrypt/libgcrypt-1.7.8/src/.libs/ 
LIB3=../../libgcrypt/libgpg-error-1.27/src/.libs
LIB4= -l gcrypt -l gpg-error -lws2_32 
CC=gcc
OPT2=-I $(INC2) -I $(INC3) -I $(INC4) -L $(LIB2) -L $(LIB3) $(LIB4)

# This is to create templates for test expectations. We substitue memory 
# locations with zeros, so diff is happy

FILTER=sed s/0x[0-9A-F]*/0x00000000/g

.c.o: 
	$(CC) $(OPT2) -c $<  
    
OBJS =  base64.o getpass.o zmalloc.o cmdline.o

all:  $(OBJS) test_base64.exe test_base64a.exe test_base64b.exe \
        test_zmalloc.exe test_comline.exe
         
tests:  build_tests
	@echo Tests pass if diffs are silent.
	@test_base64a.exe > test.tmp
	@diff test_base64a.org test.tmp
	@test_base64.exe > test.tmp
	@diff test_base64.org test.tmp
	@test_zmalloc.exe | $(FILTER) > test.tmp
	@diff test_zmalloc.org test.tmp
	@test_comline.exe > test.tmp
	@diff test_comline.org test.tmp
	@-rm -f test.tmp 
	   
build_tests: test_base64.exe test_base64a.exe  test_zmalloc.exe test_comline.exe

prep_tests:  build_tests
	@test_base64.exe > test_base64.org
	@test_base64a.exe > test_base64a.org
	@test_zmalloc.exe | $(FILTER) > test_zmalloc.org
	@test_comline.exe > test_comline.org
	             
test_base64.exe:  test_base64.c  base64.c zmalloc.c 
	gcc test_base64.c  base64.c zmalloc.c -o test_base64 

test_comline.exe:  test_base64.c  base64.c zmalloc.c cmdline.o 
	gcc test_comline.c  base64.c zmalloc.c cmdline.o -o test_comline

test_base64a.exe:  test_base64a.c  base64.c zmalloc.c 
	gcc test_base64a.c  base64.c zmalloc.c -o test_base64a 

test_base64b.exe:  test_base64b.c  base64.c zmalloc.c 
	gcc test_base64b.c  base64.c zmalloc.c -o test_base64b

test_zmalloc.exe:  test_zmalloc.c  zmalloc.c 
	gcc test_zmalloc.c  zmalloc.c -o test_zmalloc

clean:
	@-rm -f aa.*  
	@-rm -f bb.*  
	@-rm -f cc.*  
	@-rm -f *.o   
	@-rm -f test2.tmp test.tmp
	@-rm -f aa
	
allclean:  clean
	@-rm -f *.exe 
	@-rm -f aa
	




















