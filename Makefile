CC = gcc
CFLAGS = -I/usr/local/include/ -I/usr/lib64/
LIBS = -lssh2
#LDFLAGS = -L/usr/include/libssh2.h -L/usr/local/lib/
LDFLAGS = -L/usr/local/include/libssh2.h -L/usr/local/lib

all: sftp_sim

sftp_sim: sftp_sim.o
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) $^ -o $@

PHONY: clean
	sources = sftp_sim.c
	include $(sources:.c=.d)

%.d: %.c
	set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

clean:
	@echo "cleanning project"
	-rm sftp_sim *.o
	@echo "clean completed"
