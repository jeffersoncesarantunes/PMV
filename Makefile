CC = cc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -I./include -I/usr/local/include
LDFLAGS = -lkvm -pie -z relro -z now
TARGET = pmv
SRC = src/main.c src/engine.c

all: $(TARGET)
	@echo "OK Build successful!"

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

install: all
	install -m 755 -o root -g wheel $(TARGET) /usr/local/bin/pmv

clean:
	@echo "Clean."
	@rm -f $(TARGET)

.PHONY: all clean install
