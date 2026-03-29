CC = gcc
CFLAGS = -Wall -Wextra -std=c17 -D_DEFAULT_SOURCE
TARGET = ipk-L4-scan
SRC = c/main.c c/args.c c/dns.c c/port_scanner.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) -lpcap

NixDevShellName:
	@echo "c"
