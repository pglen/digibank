# These point to already built sub parts. Edit it if you move
# the files to a different directory.
# This is so one can use the parts without installation.

INC2=../../libgcrypt/libgpg-error-1.27/src 
INC3=../../libgcrypt/libgcrypt-1.7.8/src 
INC4=../bluepoint
INC5=../../zlib/zlib-1.2.11

LIB5=../../zlib/zlib-1.2.11


CC=gcc
OPT2= -I $(INC2) -I $(INC3) -I $(INC4) -I $(INC5) -L $(LIB5)
OPT3=$(OPT2) -l z
 
# This is to create templates for test expectations. We substitue memory 
# locations with zeros, so diff is happy

FILTER=sed s/0x[0-9A-F]*/0x00000000/g
FILTER2=grep -v Begin
.c.o: 
	$(CC) $(OPT2) -c $<  
    
OBJS =  base64.o getpass.o zmalloc.o cmdline.o gsexp.o misc.o dibafile.o
SRCS =  base64.c getpass.c zmalloc.c cmdline.c misc.c

all:  $(OBJS) 
 
 # misc needs filter to erase pointer strings
 # zmalloc needs filter to erase PID strings
	        
tests:  build_tests
	@echo Tests pass if diffs are silent.
	@test_two.sh test_misc.exe "$(FILTER2)"  
	@#test_two.sh test_zmalloc.exe "$(FILTER)"
	@test_one.sh test_base64.exe
	@test_one.sh test_base64a.exe
	@test_one.sh test_comline.exe
	@test_one.sh test_zstr.exe
	@test_one.sh test_zip.exe
	@test_one.sh test_chunk.exe
	@test_one.sh test_keys.exe
	@-rm -f test.tmp 
	   
build_tests: test_base64.exe test_base64a.exe test_base64b.exe \
        test_zmalloc.exe test_comline.exe test_zstr.exe \
            test_misc.exe test_chunk.exe  test_keys.exe test_zip

prep_tests:  build_tests
	@test_misc.exe | $(FILTER2) > test_misc.org 
	@test_zmalloc.exe | $(FILTER) > test_zmalloc.org
	@test_prep.sh test_base64.exe
	@test_prep.sh test_base64a.exe
	@test_prep.sh test_comline.exe
	@test_prep.sh test_zstr.exe
	@test_prep.sh test_zmalloc.exe
	@test_prep.sh test_zip.exe
	@test_prep.sh test_chunk.exe
	@test_prep.sh test_keys.exe
	             
test_base64.exe:  test_base64.o  $(OBJS)
	$(CC) test_base64.c  base64.c zmalloc.c -o test_base64 
 
test_misc.exe:  test_misc.o  $(OBJS)
	$(CC) test_misc.c  $(SRCS) -o test_misc

test_zip.exe:  test_zip.o  $(OBJS)
	 $(CC) $(OPT3) $(SRCS) dibafile.c  test_zip.c -l z -o test_zip

test_chunk.exe:  test_chunk.o  $(OBJS)
	 $(CC) $(OPT3) $(SRCS) dibafile.c  test_chunk.c -l z -o test_chunk

test_keys.exe:  test_keys.o  $(OBJS)
	$(CC)  $(OPT3) test_keys.c $(SRCS) dibafile.c -l z -o test_keys

test_zstr.exe:  test_zstr.o  $(OBJS)
	$(CC) test_zstr.c  base64.c zstr.c zmalloc.c misc.c cmdline.c -o test_zstr

test_comline.exe:  test_comline.o  $(OBJS)
	$(CC) test_comline.c  base64.c zmalloc.c cmdline.c -o test_comline

test_base64a.exe:  test_base64a.o   $(OBJS)
	$(CC) test_base64a.c  base64.c zmalloc.c -o test_base64a 

test_base64b.exe:  test_base64b.o  $(OBJS)
	$(CC) test_base64b.c  base64.c zmalloc.c -o test_base64b

test_zmalloc.exe:  test_zmalloc.o  $(OBJS)
	$(CC) test_zmalloc.c  zmalloc.c -o test_zmalloc

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
	
deepclean:  clean allclean
	@rm -f *.org






