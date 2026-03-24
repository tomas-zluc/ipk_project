CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = ipk-L4-scan
SRC = main.c args.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
