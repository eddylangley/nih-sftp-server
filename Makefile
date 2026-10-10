# Packaging-friendly build: CC/CFLAGS/LDFLAGS are only defaulted here (?=),
# never overridden - a packager's own exported flags take over completely,
# as expected by distro build systems. See README.md's "Building" section
# for the exact flags this project validates against in CI; those are only
# the *defaults* used when nothing else is set.
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=iso9899:1999 -pedantic-errors
LDFLAGS ?=

PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin

TARGET = nih-sftp-server

.PHONY: all install uninstall clean

all: $(TARGET)

$(TARGET): nih-sftp-server.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
