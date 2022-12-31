PROG=udp-bind-proxy
SRCS=proxy.c log.c filter.c
MAN=

LDADD=-levent
DPADD=${LIBEVENT}

DEBUG=-g
WARNINGS=Yes

.include <bsd.prog.mk>
