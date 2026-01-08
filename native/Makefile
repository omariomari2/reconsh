CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS = -lpthread

SRCDIR = src
INCDIR = include
BINDIR = ../bin

SOURCES = $(SRCDIR)/dns_brute.c $(SRCDIR)/dns_resolver.c
TARGET = $(BINDIR)/dns_brute

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)
	@echo "Built: $@"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"
