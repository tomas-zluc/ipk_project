CC = gcc
CFLAGS = -Wall -Wextra -std=c17 -D_DEFAULT_SOURCE
TARGET = ipk-L4-scan
SRC = main.c args.c dns.c port_scanner.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) -lpcap
