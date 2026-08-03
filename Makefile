CC=cc
CFLAGS=-std=c99 -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -Wstrict-prototypes -pedantic -I/usr/include/libxml2
LDFLAGS=-lcrypto -largon2 -lz -lxml2 -lncurses

OBJECTS=kdbx.o crypto.o keepasst.o
SRC_DIR=src
TARGET=keepasst

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

kdbx.o: $(SRC_DIR)/kdbx.c $(SRC_DIR)/kdbx.h
	$(CC) $(CFLAGS) -c -o $@ $<
	
crypto.o: $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto.h
	$(CC) $(CFLAGS) -c -o $@ $<

keepasst.o: $(SRC_DIR)/keepasst.c # $(SRC_DIR)/crypto.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm *.o

.PHONY: install
install:
	install -m 0755 ./$(TARGET) /usr/local/bin/
	install -m 0664 ./keepasst.1 /usr/local/share/man/man1/


