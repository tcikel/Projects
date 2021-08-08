CC=gcc
CXX=g++
RM=rm -f

SRCS=d6r.cpp
OBJS=d6r.o argument.o relay.o

d6r: $(OBJS)
	$(CXX) -Wall -o  d6r d6r.o argument.o relay.o  -pthread -lpcap
argument.o: argument.cpp
	$(CXX) -Wall -g -lpcap -c argument.cpp 
relay.o: relay.cpp
	$(CXX) -Wall -g -lpcap  -pthread -c relay.cpp
d6r.o: $(SRCS)
	$(CXX) -Wall -g -lpcap  -pthread -c $(SRCS)

clean:
	$(RM) $(OBJS)
distclean: clean
	$(RM) d6r

