# ------------------------------------------------------------------------
#

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -std=c99 -O2 -I$(top_srcdir)/common \
    -I$(top_srcdir)/common -I$(top_srcdir)/bluepoint -I$(top_srcdir)/tools

AM_LDFLAGS = -L$(top_srcdir)/common -L$(top_srcdir)/tools -l z -l gcrypt \
      -l gpg-error

AUTOMAKE_OPTIONS = subdir-objects

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile

bin_PROGRAMS = tests/test_base64 tests/test_zmalloc \
 tests/test_base64 tests/test_base64a tests/test_base64b \
         tests/test_comline tests/test_zstr tests/test_misc \
            tests/test_chunk tests/test_keys tests/test_zip tests/test_getpass \
                tests/test_dibabuffa tests/test_dibafile tests/test_buffkeys \
                 #tests/tests/test_buffbuff

tests_test_zmalloc_SOURCES = tests/test_zmalloc.c zmalloc.c
tests_test_base64_SOURCES = tests/test_base64.c base64.c zmalloc.c
tests_test_base64a_SOURCES = tests/test_base64a.c base64.c zmalloc.c
tests_test_base64b_SOURCES = tests/test_base64b.c base64.c zmalloc.c
tests_test_comline_SOURCES = tests/test_comline.c base64.c zmalloc.c misc.c cmdline.c zstr.c
tests_test_zstr_SOURCES = tests/test_zstr.c base64.c zmalloc.c misc.c cmdline.c zstr.c
tests_test_misc_SOURCES = tests/test_misc.c base64.c zmalloc.c misc.c cmdline.c zstr.c
tests_test_getpass_SOURCES = tests/test_getpass.c base64.c zmalloc.c misc.c cmdline.c zstr.c getpass.c

tests_test_keys_SOURCES = tests/test_keys.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c dibafile.c
tests_test_zip_SOURCES = tests/test_zip.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c  dibafile.c
tests_test_chunk_SOURCES = tests/test_chunk.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c dibafile.c
tests_test_dibabuffa_SOURCES = tests/test_dibabuffa.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c
tests_test_dibafile_SOURCES = tests/test_dibabuffa.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c
tests_test_buffkeys_SOURCES = tests/test_buffkeys.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c
#tests_test_buffbuff_SOURCES = tests/test_buffbuff.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c

test:
	@echo Tests pass if diffs are silent.
	@./tests/test_one.sh ./tests/test_base64$(EXEEXT)
	@./tests/test_one.sh ./tests/test_base64a$(EXEEXT)
	@./tests/test_one.sh ./tests/test_comline$(EXEEXT)
	@./tests/test_one.sh ./tests/test_zstr$(EXEEXT)
	@./tests/test_one.sh ./tests/test_keys$(EXEEXT)
	@./tests/test_one.sh ./tests/test_chunk$(EXEEXT)
	@./tests/test_one.sh ./tests/test_dibabuffa$(EXEEXT)
	@./tests/test_one.sh ./tests/test_zip$(EXEEXT)
	@./tests/test_two.sh ./tests/test_misc$(EXEEXT) "$(FILTER2)"
	@./tests/test_two.sh ./tests/test_zmalloc$(EXEEXT) "$(FILTER)"
	@-rm -f test.tmp

prep_tests:
	@./tests/test_prep2.sh ./tests/test_zmalloc$(EXEEXT) "$(FILTER)"
	@./tests/test_prep2.sh ./tests/test_misc$(EXEEXT) "$(FILTER2)"
	@./tests/test_prep.sh ./tests/test_base64$(EXE$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_base64a$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_comline$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_zstr$(EXEE$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_dibabuffa$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_zip$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_chunk$(EXEEXT)
	@./tests/test_prep.sh ./tests/test_keys$(EXEEXT)
	@echo Please press ENTER key for getpass
	@./tests/test_prep.sh ./tests/test_getpass$(EXEEXT)

tests/test_PROGRAMS:  ./tests/test_base64$(EXEEXT)

clean-local:
	rm -f *.exe











