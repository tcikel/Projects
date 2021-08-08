
CC = g++


CFLAGS = -g -Wall -std=c++17
LDFLAGS = 
OBJFILES = main.o scanner.o
TARGET = main

all: $(TARGET)

$(TARGET) : $(OBJFILES)
			$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) -lssl -lcrypto

scanner.o: 	scanner.h
				$(CC) $(CFLAGS) -c scanner.cpp 

main.o : scanner.h
				$(CC) $(CFLAGS) -c main.cpp

clean: 
		$(RM) $(OBJFILES)