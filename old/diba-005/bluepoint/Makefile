



all: block_blue2.exe test_blue2.exe

block_blue2.exe: hs_crypt.c
	gcc block_blue2.c bluepoint2.c -o block_blue2.exe

test_blue2.exe:
	gcc test_blue2.c bluepoint2.c -o test_blue2.exe

tests:  test_blue2.exe
	@test_blue2.exe > test.tmp
	@echo "Test passes if diff is silent."
	@diff test.org test.tmp
	@-rm test.tmp
    
clean:
	@-rm *.o
	@-rm *.exe
    
