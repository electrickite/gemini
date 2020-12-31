.POSIX:

SERVER = agena
CLIENT = glv

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
LD = ld
CFLAGS = -std=c99 -pedantic -Wall -Wextra -Werror -Wno-unused-parameter -Os -s
LDLIBS = -L./lib -lssl -lcrypto -lmagic -luriparser

DEPS = version.h lib/common.h lib/protocol.h
LIB_SRC = $(wildcard lib/*.c)
MIME_SRC = $(wildcard lib/xdgmime/*.c)
SERVER_OBJ = server.o
CLIENT_OBJ = client.o
LIB_OBJ = $(LIB_SRC:%.c=%.o)
MIME_OBJ = $(MIME_SRC:%.c=%.o)
OBJ = $(SERVER_OBJ) $(CLIENT_OBJ) $(LIB_OBJ)
TARGETS = $(CLIENT) $(SERVER)

all: $(TARGETS)

$(MIME_OBJ):
	$(MAKE) -C lib/xdgmime $(@F)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(CLIENT): $(CLIENT_OBJ) $(LIB_OBJ)
$(SERVER): $(SERVER_OBJ) $(LIB_OBJ) $(MIME_OBJ)

$(TARGETS):
	$(CC) $(LDLIBS) -o $@ $^ $(LDFLAGS)

clean:
	@echo cleaning
	$(RM) $(TARGETS) $(OBJ)
	$(MAKE) -C lib/xdgmime clean

install: all
	@echo installing in $(DESTDIR)$(PREFIX)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(TARGETS) $(DESTDIR)$(PREFIX)/bin
	chmod 755 $(DESTDIR)$(PREFIX)/bin/$(CLIENT) $(DESTDIR)$(PREFIX)/bin/$(SERVER)

uninstall:
	@echo removing files from $(DESTDIR)$(PREFIX)
	$(RM) $(DESTDIR)$(PREFIX)/bin/$(CLIENT) $(DESTDIR)$(PREFIX)/bin/$(SERVER)
