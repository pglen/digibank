LDFLAGS = -lgcrypt
CXXFLAGS = -std=c++11 -Wall -Wextra -g -I ../../src -I ../../../libgpg-error-1.27/src \
    -L ../../src/.libs/

BINS = keygen main
OBJS = gcry.o getpass.o

all: $(BINS)

keygen: $(OBJS)
	$(CXX) $(CXXFLAGS) keygen.cc $(OBJS) -o keygen $(LDFLAGS)

main: $(OBJS)
	$(CXX) $(CXXFLAGS) main.cc $(OBJS) -o main $(LDFLAGS)

gcry.o: gcry.cc

getpass.o: getpass.cc

clean:
	rm -f *.o $(BINS)


