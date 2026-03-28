CC=gcc
CFLAGS=-Wall -g

ODIR=obj
LDIR =../lib

LIBS=
LIBS_PROXY=-lsodium

SRCS=server.c client.c proxy.c

OBJ = $(patsubst %.c,$(ODIR)/%.o,$(SRCS))

all: server client proxy
$(ODIR)/%.o: %.c 
	@mkdir -p $(ODIR)
	$(CC) $(CFLAGS) -c $< -o $@ 

server: $(ODIR)/server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
client: $(ODIR)/client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
proxy: $(ODIR)/proxy.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS_PROXY)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o server client proxy
