
CFLAGS= -std=c11 -Wall -Werror -O2 -D_DEFAULT_SOURCE
LDFLAGS= -lssl -lcrypto
PROGNAME= rcmd

.PHONY: all clean

default: all

all: $(PROGNAME)
	@ls -li $(PROGNAME)

$(PROGNAME): rcmd.c
	gcc $(CFLAGS) $(LDFLAGS) rcmd.c -o $(PROGNAME)

clean:
	@rm -v $(PROGNAME) 2>/dev/null || true

