CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto  
OBJECTS = myproxy.o
SRCDIR = src
BINDIR = bin

.PHONY: all clean

all: $(BINDIR)/myproxy

$(BINDIR)/myproxy: $(OBJECTS)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(BINDIR)/myproxy $(LDFLAGS)	
	cp $(BINDIR)/myproxy ./

myproxy.o: $(SRCDIR)/myproxy.cpp
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/myproxy.cpp

clean: 
	rm -f *.o
	rm -f $(BINDIR)/myproxy
	rm -f myproxy