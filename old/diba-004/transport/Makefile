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
ENCTEST=dibaencrypt.exe -i sample.txt -o sample.enc testkey.pub  
ENCTEST2=dibadecrypt.exe -i sample.enc -o sample.dec -p 1111 testkey.key
KEYTEST=dibakeygen.exe -p 1111 -f bb  
KEYTEST2=dibakeyinfo.exe -p 1111 -c bb  

HELLO="Hello World"
ENCTEST3=echo $(HELLO) | dibaencrypt.exe -r testkey.pub | dibadecrypt.exe -r -p 1111 testkey.key

.c.o: 
	$(CC) $(OPT2) -c $<  
    
OBJS =  base64.o gcry.o getpass.o zmalloc.o gsexp.o bluepoint2.o cmdline.o

all:  dibakeygen.exe dibaencrypt.exe dibadecrypt.exe \
        dump.exe dibakeyinfo.exe algos.exe
         
bluepoint2.o:
	$(CC) $(OPT2) -c ../bluepoint/bluepoint2.c  

tests:  build_tests
	@echo Tests pass if diffs are silent.
	@test_base64a.exe > test.tmp
	@diff test_base64a.org test.tmp
	@test_base64.exe > test.tmp
	@diff test_base64.org test.tmp
	@test_zmalloc.exe | $(FILTER) > test.tmp
	@diff test_zmalloc.org test.tmp
	@$(ENCTEST); $(ENCTEST2)
	@diff sample.txt sample.dec
	@echo $(HELLO) > test2.tmp
	@$(ENCTEST3) > test.tmp
	@diff -w test2.tmp test.tmp
	@$(KEYTEST) > test2.tmp; $(KEYTEST2) > test2.tmp
	@cat test2.tmp | grep OK > test.tmp
	@diff test.tmp keytest.org 
	@-rm test2.tmp test.tmp 
	   
build_tests: test_base64.exe test_base64a.exe  test_zmalloc.exe dibaencrypt.exe dibadecrypt.exe \
            dump.exe dibakeygen.exe dibakeyinfo.exe

prep_tests:  build_tests
	@test_base64.exe > test_base64.org
	@test_base64a.exe > test_base64a.org
	@test_zmalloc.exe | $(FILTER) > test_zmalloc.org
	$(ENCTEST) > enctest.org
	@$(KEYTEST) > test.tmp; $(KEYTEST2) > test.tmp
	@cat test.tmp | grep OK > keytest.org 
	@rm test.tmp
	             
algos.exe: $(OBJS) algos.c
	$(CC) algos.c $(OBJS) $(OPT2) -o algos

dibakeygen.exe: $(OBJS) dibakeygen.c
	$(CC) dibakeygen.c $(OBJS) $(OPT2) -o dibakeygen

dibakeyinfo.exe: $(OBJS) dibakeyinfo.c
	$(CC) dibakeyinfo.c $(OBJS) $(OPT2) -o dibakeyinfo

encdec.exe: $(OBJS) encdec.c
	$(CC) encdec.c $(OBJS) $(OPT2) -o encdec

dibaencrypt.exe: $(OBJS) dibaencrypt.c
	$(CC) dibaencrypt.c $(OBJS) $(OPT2) -o dibaencrypt

dibadecrypt.exe: $(OBJS) dibadecrypt.c
	$(CC) dibadecrypt.c $(OBJS) $(OPT2) -o dibadecrypt

test_base64.exe:  test_base64.c  base64.c zmalloc.c 
	gcc test_base64.c  base64.c zmalloc.c -o test_base64 

test_base64a.exe:  test_base64a.c  base64.c zmalloc.c 
	gcc test_base64a.c  base64.c zmalloc.c -o test_base64a 

test_zmalloc.exe:  test_zmalloc.c  zmalloc.c 
	gcc test_zmalloc.c  zmalloc.c -o test_zmalloc

dump.exe:  $(OBJS) dump.c
	$(CC) dump.c  $(OBJS) $(OPT2) -o dump.exe

clean:
	@-rm aa.*      >aa  2>&1 
	@-rm bb.*      >aa  2>&1 
	@-rm cc.*      >aa  2>&1 
	@-rm *.exe     >aa  2>&1 
	@-rm *.o       >aa  2>&1 
	@-rm test2.tmp test.tmp 
	@-rm aa
	

















