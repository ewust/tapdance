
CFLAGS+=-g -O2
LDFLAGS+=-lpcap -levent /home/ewust/research/PF_RING/userland/lib/libpfring.a

all: station


station: station.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
