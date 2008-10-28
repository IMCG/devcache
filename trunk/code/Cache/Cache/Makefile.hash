CC= gcc
CFLAGS= -Wall -O2
INCLUDES= -I. -I/usr/include/
LIBS=
README=Readme
EXEC= test_hashtable

all: test_hashtable.c list.h hash_table.h Makefile
	$(CC) $(CFLAGS) $(INCLUDES) test_hashtable.c -o $(EXEC) $(LIBS)

beauty:
	@indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.[c,h];
	@rm -f *.[c,h]~;

clean:
	@rm -rf *.o *~ $(EXEC) core.* core

sense:
	@more $(README)
