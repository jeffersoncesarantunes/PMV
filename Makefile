CC = cc
CFLAGS = -Wall -Wextra -O2 -I./include -I/usr/local/include
LDFLAGS = -lkvm
TARGET = pmv
SRC = src/main.c src/engine.c

all: $(TARGET)
	@echo "🟢 Build successful!"

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

install: all
	install -m 755 -o root -g wheel $(TARGET) /usr/local/bin/pmv

clean:
	@echo "🧹 Clean."
	@rm -f $(TARGET)

.PHONY: all clean install
