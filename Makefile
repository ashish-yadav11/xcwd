PREFIX = /usr/local

CC = gcc
CFLAGS = -O3 -Wall -Wextra

xcwd: xcwd.c
	${CC} -o $@ ${CFLAGS} `pkg-config --cflags x11` xcwd.c `pkg-config --libs x11`

clean:
	rm -f xcwd

install: xcwd
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f xcwd ${DESTDIR}${PREFIX}/bin/xcwd
	chmod 755 ${DESTDIR}${PREFIX}/bin/xcwd

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/xcwd

.PHONY: clean install uninstall
