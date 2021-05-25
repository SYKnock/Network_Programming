CC=gcc
CFLAGS= -g -I.

DEPS = arp.h dns.h http.h https.h dhcp.h

OBJ = supa.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

supa: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf *.o supa

