# These point to already built sub parts. Edit it if you move the files to 
# a different directory. This is done, so one can use the parts without 
# explicit installation.

# History
#   0.00  aug.26.2017     Peter Glen      First push to github

CC=gcc

INC2=../../libgcrypt/libgpg-error-1.27/src 
INC3=../../libgcrypt/libgcrypt-1.7.8/src 
INC4=../bluepoint
INC5=../tools

LIB2=../../libgcrypt/libgcrypt-1.7.8/src/.libs/ 
LIB3=../../libgcrypt/libgpg-error-1.27/src/.libs/
LIB4= -l gcrypt -l gpg-error 
#LIB4= -l gcrypt -l gpg-error  -lws2_32 

OPT2= -I $(INC2) -I $(INC3) -I $(INC4) -I $(INC5) -L $(LIB2) -L $(LIB3) $(LIB4)

TOOLDIR=../tools
BLUEDIR=../bluepoint

# This is to create templates for test expectations. We substitue memory 
# locations with zeros, so diff is happy

FILTER=sed s/0x[0-9A-F]*/0x00000000/g

# Test macros

ENCTEST=dibaencrypt.exe -i sample.txt -o sample.enc testkey.pub  
ENCTEST2=dibadecrypt.exe -i sample.enc -o sample.dec -p 1111 testkey.key

ENCTEST3=dibaencrypt.exe -i blocksample.txt -o blocksample.enc testkey.pub  
ENCTEST4=dibadecrypt.exe -i blocksample.enc -o blocksample.dec -p 1111 testkey.key

KEYTEST=dibakeygen.exe -p 1111 -f bb  
KEYTEST2=dibakeyinfo.exe -p 1111 -c bb  

HELLO="Hello World"
ENCTEST5=echo $(HELLO) | dibaencrypt.exe -r testkey.pub | dibadecrypt.exe -r -p 1111 testkey.key

.c.o: 
	$(CC) $(OPT2) -c $<  
    
OBJS  =   gcry.c gsexp.c dibastr.c

CRYPTER = $(BLUEDIR)/bluepoint2.c 

TOOLS=$(TOOLDIR)/base64.c $(TOOLDIR)/getpass.c $(TOOLDIR)/zmalloc.c \
                $(TOOLDIR)/cmdline.c

# Tried vpath
#VPATH = . $(TOOLDIR) $(BLUEDIR)
#vpath %.c $(TOOLDIR) $(BLUEDIR)
#vpath %.h $(TOOLDIR) $(BLUEDIR)

#CRYPTER = bluepoint2.c 
#TOOLS =   base64.c getpass.c zmalloc.c cmdline.c

all:  dibakeygen.exe dibaencrypt.exe dibadecrypt.exe dibakeyinfo.exe

bluepoint2.o:
	$(CC) $(OPT2) -c ../bluepoint/bluepoint2.c  

bigtest: build_tests
	@cat bigsample.txt >test.tmp ;cat bigsample.txt >test.tmp
	@cat bigsample.txt >>test.tmp ;cat bigsample.txt >>test.tmp
	dibaencrypt.exe   -i test.tmp -o test.enc testkey.pub 
	dibadecrypt.exe  -i test.enc -o test.dec -p 1111 testkey.key 
	@echo Test passes if diffs are silent.
	diff test.tmp test.dec    

tests:  build_tests 
	@echo Tests pass if diffs are silent.
	@$(ENCTEST); $(ENCTEST2)
	@diff sample.txt sample.dec
	@$(ENCTEST3); $(ENCTEST4)
	@diff blocksample.txt blocksample.dec
	@echo $(HELLO) > test2.tmp
	@$(ENCTEST5) > test.tmp
	@diff -w test2.tmp test.tmp
	@$(KEYTEST) > test2.tmp; $(KEYTEST2) > test2.tmp
	@cat test2.tmp | grep OK > test.tmp
	@diff test.tmp keytest.org 
	@-rm -f test2.tmp test.tmp *.enc *.dec 
    
build_tests: dibaencrypt.exe dibadecrypt.exe dibakeygen.exe dibakeyinfo.exe

enctest.org:
	$(ENCTEST) > enctest.org
       
prep_tests:  build_tests enctest.org
	@$(KEYTEST) > test.tmp; $(KEYTEST2) > test.tmp
	@cat test.tmp | grep OK > keytest.org 
	@rm test.tmp
	             
algos.exe: $(OBJS) algos.c  $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(OPT2) -o $@

test_sexp.exe: $(OBJS) test_sexp.c  $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(OPT2) -o $@

dibakeygen.exe:  dibakeygen.c $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(OPT2) -o $@

dibakeyinfo.exe: $(OBJS) dibakeyinfo.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(OPT2) -o $@

dibaencrypt.exe: $(OBJS) dibaencrypt.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(OPT2) -o $@

dibadecrypt.exe: $(OBJS) dibadecrypt.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(OPT2) -o $@

dump.exe:  $(OBJS) dump.c $(TOOLS)
	$(CC)  $^ $(OPT2) -o $@

clean:
	@-rm -f aa.* bb.* cc.*  
	@-rm -f *.o  *.enc *.dec
	@-rm -f test2.tmp test.tmp 
	@-rm -f aa
	
allclean:  clean
	@-rm -f *.exe  *.org
	@-rm -f aa

	
























