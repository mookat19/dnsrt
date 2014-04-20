all: dnsrt

dtsrouted: dnsrt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -lrt -o $@ $<

clean:
	rm -f dnsrt
