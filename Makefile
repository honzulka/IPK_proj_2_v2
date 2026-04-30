CC = gcc
CFLAGS = -std=gnu17 -Wall -Wextra -Werror

TARGET = ipk-rdt

SRCS =  src/main.c \
	src/client.c \
	src/server.c \
	src/protocol.c

PACK = xcernoj00
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

pack: clean $(PACK).tar

$(PACK).tar: 
	tar -cvf $@ src/*.h src/*.c Makefile tests/test_all.py

clean:
	rm -f $(TARGET) $(PACK).tar

test: $(TARGET)
	python3 tests/test_all.py

.PHONY: all clean pack test
