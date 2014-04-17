all: dnsrt

dnsrouted: dnsrt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f dnsrt
