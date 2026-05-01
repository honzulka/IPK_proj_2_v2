CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Werror

TARGET = ipk-rdt

SRCS =  src/main.c \
	src/client.c \
	src/server.c \
	src/protocol.c

PACK = xcernoj00

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

pack: clean $(PACK).zip

NixDevShellName:
	@echo c

$(PACK).zip:
	zip -r $@ src/*.h src/*.c Makefile tests/test_all.py LICENSE README.md CHANGELOG.md image.png

clean:
	rm -f $(TARGET) $(PACK).zip

test: $(TARGET)
	python3 tests/test_all.py

.PHONY: all clean pack test NixDevShellName
