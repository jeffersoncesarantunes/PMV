CC = cc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -I./include -I/usr/local/include
LDFLAGS = -lkvm -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
TARGET = pmv
SRC = src/main.c src/engine.c src/score.c src/util.c
PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man/man1
FUZZ_CC ?= clang
FUZZ_TIME ?= 60

all: $(TARGET)
	@echo "✅ Build successful!"

$(TARGET): $(SRC) include/pmv.h
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
	@rm -f $(TARGET) tests/test_pmv tests/fuzz/fuzz_snapshot

test: test-unit

test-unit:
	@echo "🧪 Running unit tests..."
	@$(CC) -Wall -Wextra $(CFLAGS) tests/test_pmv.c src/util.c src/score.c -o tests/test_pmv
	@./tests/test_pmv
	@rm -f tests/test_pmv

verify: test-unit
	@if [ "$$(uname -s)" = "OpenBSD" ]; then \
		echo "🧭 Running OpenBSD integration tests..."; \
		${MAKE} all && sh tests/integration/run.sh; \
	else \
		echo "⏭️  Skipping integration tests (requires OpenBSD)."; \
	fi

bench: all
	@sh scripts/bench.sh ./pmv

fuzz: tests/fuzz/fuzz_snapshot

tests/fuzz/fuzz_snapshot: tests/fuzz/fuzz_snapshot.c src/util.c include/pmv.h
	@$(FUZZ_CC) -g -O1 -fno-omit-frame-pointer \
		-fsanitize=fuzzer,address,undefined -I./include \
		tests/fuzz/fuzz_snapshot.c src/util.c -o tests/fuzz/fuzz_snapshot

fuzz-run: fuzz
	@tmp=$$(mktemp -d); cp tests/fuzz/corpus/* $$tmp/; \
		./tests/fuzz/fuzz_snapshot -max_total_time=$(FUZZ_TIME) $$tmp; \
		status=$$?; rm -rf -- $$tmp; exit $$status

.PHONY: all clean install install-man uninstall test test-unit verify bench fuzz fuzz-run
