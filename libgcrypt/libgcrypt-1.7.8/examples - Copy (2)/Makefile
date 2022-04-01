# These point to already built sub parts

INC2=../../libgpg-error-1.27/src 
INC3=../src 
LIB2=../src/.libs/ 
LIB3=../../libgpg-error-1.27/src/.libs
LIB4= -l gcrypt -l gpg-error 
CC=gcc
OPT2=-I $(INC2) -I $(INC3) -L $(LIB2) -L $(LIB3) $(LIB4)

.c.o:
	$(CC) $(OPT2) -c $<  
    
OBJS = gcry.o getpass.o zmalloc.o base64.o

all:  encrypt.exe keygen.exe encdec.exe asencrypt.exe asdecrypt.exe dump.exe
      
tests:  test_base64.exe test_zmalloc.exe

encrypt.exe:  encrypt.c  zmalloc.c 
	$(CC) encrypt.c  $(OPT2) zmalloc.c -o encrypt

keygen.exe: $(OBJS) keygen.c
	$(CC) keygen.c $(OBJS) $(OPT2) -o keygen

encdec.exe: $(OBJS) encdec.c
	$(CC) encdec.c $(OBJS) $(OPT2) -o encdec

asencrypt.exe: $(OBJS) asencrypt.c
	$(CC) asencrypt.c $(OBJS) $(OPT2) -o asencrypt

asdecrypt.exe: $(OBJS) asdecrypt.c
	$(CC) asdecrypt.c $(OBJS) $(OPT2) -o asdecrypt

test_base64.exe:  test_base64.c  base64.c zmalloc.c 
	gcc test_base64.c  base64.c zmalloc.c -o test_base64 

test_zmalloc.exe:  test_zmalloc.c  zmalloc.c 
	gcc test_zmalloc.c  zmalloc.c -o test_zmalloc

dump.exe:  $(OBJS) dump.c
	$(CC) dump.c  $(OBJS) $(OPT2) -o dump.exe

clean:
	@-rm a.exe      >aa  2>&1 
	@-rm *.exe      >aa  2>&1 
	@-rm *.o      >aa  2>&1 
	@-rm encrypt.exe >aa 2>&1 
	@-rm aa











