# Makefile for console digibank client

all:    digibank dibagen dibadec

test:   test_blue2.c block_blue2.c
	gcc -o test_blue2 test_blue2.c bluepoint2.c
	gcc -o block_blue2 block_blue2.c bluepoint2.c

digibank:  digibank.c bluepoint2.c  bluepoint2.h diba.h
	gcc -o digibank digibank.c bluepoint2.c

dibagen:  dibagen.c bluepoint2.c  bluepoint2.h diba.h
	gcc -o dibagen dibagen.c bluepoint2.c

dibadec:  dibadec.c bluepoint2.c  bluepoint2.h diba.h
	gcc -o dibadec dibadec.c bluepoint2.c

clean:
	rm -f *~
	rm -f \#*
	rm -f a.out








