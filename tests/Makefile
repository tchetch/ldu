CC=gcc
RM=rm
CFLAGS=-DLDU_ALLOCATOR="\"ldu_stdlib_alloc.h\"" -lcheck  -lldap -I./../ -Wall -g

ldu-test: ldu_test.c ../ldap_dev_utils.c
	$(CC) $+ $(CFLAGS) -o $@

all: ldu-test

clean: ldu-test
	$(RM) ldu-test
