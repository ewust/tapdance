#INCLUDE=-I./req/local/include
#LIB=-L./req/local/lib
INCLUDE=-I/usr/include -I../Elligator/
LIB=-L/usr/lib -lgmp

# Uncomment these 2 lines if you installed openssl/libevent
# to the default location /usr/local (e.g. no ./configure --prefix=)
#INCLUDE=-I/usr/local/include
#LIB=-L/usr/local/lib

CFLAGS=-O3 -g -Wall $(INCLUDE) \
	-Wformat=2 -Wno-format-nonliteral \
	-fno-strict-aliasing \
	-Wextra \
	-Wfloat-equal -Wundef -Wwrite-strings -Wredundant-decls \
	-Wnested-externs -Wbad-function-cast -Winit-self \
	-Wmissing-noreturn \
	-Wstack-protector \
	-fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1
LDFLAGS=$(LIB) -lssl -lcrypto -levent_core -levent_extra -levent_openssl -largtable2 -ldl -z relro -z now

OBJS=listener.o logger.o proxy.o ssl.o util.o client.o ../Elligator/elligator2.o ../Elligator/curve25519-donna.o
TARGETS=telex-client

all: $(TARGETS)

telex-client: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

.PHONY: clean
clean:
	-rm -f $(TARGETS)
	-rm -f $(OBJS)
