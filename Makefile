CC=gcc
CFLAGS= -Wall -g -I.

DEPS = arp.h dns.h http.h https.h dhcp.h

OBJ = limited_wireshark.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

limited_wireshark: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf *.o limited_wireshark

