CC = gcc
CFLAGS =  -std=c11 -O2
INCLUDES = -I../
TARGET = test_siphash
SRC = test_siphash.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

