# History
#   0.00  aug.27.2017     Peter Glen      Second push to github


CC=gcc
INC2=../tools
OPT2= -I $(INC2) 
TOOLDIR=../tools

TOOLS=$(TOOLDIR)/base64.c $(TOOLDIR)/getpass.c $(TOOLDIR)/zmalloc.c \
                $(TOOLDIR)/cmdline.c $(TOOLDIR)/misc.c blueutil.c

all:  blueencrypt.exe bluedecrypt.exe 

build_tests: block_blue2.exe test_blue2.exe test_blue3.exe \
         test_dump.exe blueencrypt.exe bluedecrypt.exe

block_blue2.exe: hs_crypt.c
	gcc block_blue2.c bluepoint2.c -o block_blue2.exe

test_blue2.exe:
	gcc test_blue2.c bluepoint2.c -o test_blue2.exe

test_blue3.exe: test_blue3.c bluepoint3.c bluefunc.c
	gcc test_blue3.c bluepoint3.c -o test_blue3.exe

test_dump.exe: test_dump.c bluepoint3.c bluefunc.c
	gcc test_dump.c bluepoint3.c -o test_dump.exe

blueencrypt.exe: blueencrypt.c bluepoint3.c $(TOOLS) 
	$(CC)  $^ $(OPT2) -o $@

bluedecrypt.exe: bluedecrypt.c bluepoint3.c $(TOOLS) 
	$(CC)  $^ $(OPT2) -o $@

# Test pass if diff is silent.

alltests: tests pipetest ciphertest

tests:  test_blue3.exe block_blue2.exe \
            blueencrypt.exe bluedecrypt.exe test_dump.exe
	@echo "Test passes if diff is silent."
	@blueencrypt -i test.org -f -o test.tmp -p 1111
	@bluedecrypt -i test.tmp -f  -o test.dec -p 1111
	@diff test.org test.dec

# Note: cypher cannot have a pipe in its path (binary fidelity)
# To have ciphertext compatibility, use pipe on both enc / dec
	
pipetest:
	@echo "Test passes if diff is silent."
	@cat test.org | blueencrypt -r -f -o test.tmp -p 1111
	@bluedecrypt -i test.tmp -d -f -p 1111 > test.dec
	diff test.org test.dec
 
ciphertest:
	@echo "Test passes if diff is silent."
	@test_blue3.exe > test.tmp
	diff test.org test.tmp
	       
clean:
	@-rm -f aa bb aa.* bb.*
	@-rm -f *.o  test.tmp test.dec

allclean: clean
	@-rm -f *.exe







