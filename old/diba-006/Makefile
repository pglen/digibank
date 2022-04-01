# ----------------------------------------------------------------------------------
# Makefile for console digibank client
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

# ----------------------------------------------------------------------------------

all:
	make -C tools
	make -C bluepoint
	make -C transport
	make -C blockchain
	make -C currency

# Notice the plural on tests in subdirs.

test: tests

tests: 
	make -C tools tests
	make -C bluepoint tests
	make -C transport tests
	make -C blockchain tests
	make -C currency tests

clean:
	make -C tools clean
	make -C bluepoint clean
	make -C transport clean
	make -C blockchain clean
	make -C currency clean
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe

checksum:
    # we use a file for stderr instead of /dev/nul as in MSYS /dev does ot exist
	@-rm -f md5sum.txt
	@-md5sum `find . -path ./.git -prune -o -print`  > md5sum.txt 2> ~/stderr
	@rm -f aa

check:
	@# Filter out good responses, so we see better
	-md5sum  -c md5sum.txt | grep -v "OK"








