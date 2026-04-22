CC = gcc
CFLAGS = -std=gnu17 -Wall -Wextra -Werror

TARGET = secret

SRCS =  src/main.c \
		src/client.c \
		src/server.c \
		src/protocol.c \
		src/crypto.c

PACK = xcernoj00
TEST_CMD = python3 tests/test_all.py

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

pack: clean $(PACK).tar

$(PACK).tar: 
	tar -cvf $@ src/*.h src/*.c Makefile secret.1 manual.pdf tests/test_all.py

clean:
	rm -f $(TARGET) $(PACK).tar

test: $(TARGET)
	@echo "Running ALL tests with sudo (you may be prompted for your password)..."
	sudo $(TEST_CMD)

.PHONY: all clean pack test 
