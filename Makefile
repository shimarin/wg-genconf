PREFIX ?= /usr/local
PROGNAME = wg-genconf
LIBS = -lcrypto

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).cpp
	g++ -std=c++23 -o $@ $< $(LIBS)

clean:
	rm -f $(PROGNAME)

install:
	install -Dm755 $(PROGNAME) $(DESTDIR)$(PREFIX)/bin/$(PROGNAME)
