CC=gcc
FLAGS=-Wall -pedantic -std=c99
LINK_AES=-lcrypto
SOURCES=src/main.c src/crypt.c src/util.c src/records.c src/passman.c src/skein/skein.c src/skein/skein_block.c
NAME=mypass


default:
	$(CC) $(FLAGS) $(SOURCES) $(LINK_AES) -o $(NAME)

install:
	mv $(NAME) /usr/local/bin
