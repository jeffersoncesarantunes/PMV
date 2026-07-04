CC = cc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -I./include -I/usr/local/include
LDFLAGS = -lkvm -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
TARGET = pmv
SRC = src/main.c src/engine.c
PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man/man1

all: $(TARGET)
	@echo "✅ Build successful!"

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	@strip $(TARGET)

install: all install-man
	@install -m 755 -o root -g wheel $(TARGET) $(BINDIR)/pmv
	@echo "  📄 Installed man page to $(MANDIR)"

install-man:
	@mkdir -p $(MANDIR)
	@install -m 644 man/pmv.1 $(MANDIR)/pmv.1

uninstall:
	@rm -f $(BINDIR)/pmv
	@rm -f $(MANDIR)/pmv.1
	@-rmdir $(MANDIR) 2>/dev/null; true
	@echo "  🗑 Removed pmv"

clean:
	@echo "🧹 Clean."
	@rm -f $(TARGET)

.PHONY: all clean install install-man uninstall
