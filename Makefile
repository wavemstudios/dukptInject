CC=arm-linux-gcc

all:executable

debug: CC += -g -DDEBUG
debug: executable

executable: dukptInject.c
	$(CC) dukptInject.c -o dukptInject -lfepkcs11 -lcrypto
	fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 --infile dukptInject
	
.PHONY: clean
clean:
	rm -f dukptInject dukptInject.backup
