CC=gcc
FLAGS=-Wall -pedantic -std=c99 -fstack-protector-strong -Wextra
LINK_AES=-lcrypto
SOURCES=src/main.c src/crypt.c src/util.c src/records.c src/passman.c src/skein/skein.c src/skein/skein_block.c
NAME=mypass
MCK=-O1 -g -fsanitize=address -fno-omit-frame-pointer

default:
	$(CC) $(FLAGS) $(SOURCES) $(LINK_AES) -o $(NAME)

install:
	mv $(NAME) /usr/local/bin

memcheck:
	clang $(MCK) $(SOURCES) $(LINK_AES) -o test
