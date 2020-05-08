.POSIX:

SERVER = agena
CLIENT = glv

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
LD = ld
CFLAGS = -std=c99 -pedantic -Wall -Wextra -Werror -Wno-unused-parameter -Os -s
LDLIBS =

DEPS = version.h
SERVER_OBJ = server.o
CLIENT_OBJ = client.o
OBJ = $(SERVER_OBJ) $(CLIENT_OBJ)
TARGETS = $(CLIENT) $(SERVER)

all: $(TARGETS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(CLIENT): $(CLIENT_OBJ)
$(SERVER): $(SERVER_OBJ)

$(TARGETS):
	$(CC) $(LDLIBS) -o $@ $^ $(LDFLAGS)

clean:
	@echo cleaning
	$(RM) $(TARGETS) $(OBJ)

install: all
	@echo installing in $(DESTDIR)$(PREFIX)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(TARGETS) $(DESTDIR)$(PREFIX)/bin
	chmod 755 $(DESTDIR)$(PREFIX)/bin/$(CLIENT) $(DESTDIR)$(PREFIX)/bin/$(SERVER)

uninstall:
	@echo removing files from $(DESTDIR)$(PREFIX)
	$(RM) $(DESTDIR)$(PREFIX)/bin/$(CLIENT) $(DESTDIR)$(PREFIX)/bin/$(SERVER)
