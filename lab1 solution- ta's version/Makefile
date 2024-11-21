CC=gcc
OPENSSL=./openssl
INCLUDE=$(OPENSSL)/include/
KYBER=./kyber512
KEXTRAS=$(KYBER)/fips202.c $(KYBER)/randombytes.c

.PHONY: p1 p3 plot copy_files

all: p1 plot p3 p4

p1: aes.o rsa.o kyber.o
	./aes.o > aes.txt
	./rsa.o > rsa.txt
	./kyber.o > kyber.txt

p3: client.o
	./client.o > secret.txt

p4: client_kyber.o
	./client_kyber.o > secret_kyber.txt

plot: aes.txt rsa.txt
	python3 plot_p1.py

aes.o: aes.c timer.c
	$(CC) aes.c -w -I$(INCLUDE) -L$(OPENSSL) -o aes.o $(OPENSSL)/libcrypto.a -ldl

rsa.o: rsa.c timer.c
	$(CC) rsa.c -w -I$(INCLUDE) -L$(OPENSSL) -o rsa.o $(OPENSSL)/libcrypto.a -ldl

kyber.o: kyber.c timer.c copy_files
	$(CC) kyber.c -L$(KYBER) -o kyber.o $(KYBER)/libkyber512_clean.a $(KEXTRAS) -lkyber512_clean

client.o: client.c timer.c
	$(CC) client.c -w -I $(INCLUDE) -L$(OPENSSL) -o client.o $(OPENSSL)/libcrypto.a -ldl

server.o: server.c
	$(CC) server.c -w -I$(INCLUDE) -L$(OPENSSL) -o server.o $(OPENSSL)/libcrypto.a -ldl -lpthread

client_kyber.o: client_kyber.c
	$(CC) client_kyber.c -w -I $(INCLUDE) -L$(OPENSSL) -L$(KYBER) -o client_kyber.o $(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a $(KEXTRAS) -ldl -lkyber512_clean

server_kyber.o: server_kyber.c
	$(CC) server_kyber.c -w -I $(INCLUDE) -L$(OPENSSL) -L$(KYBER) -o server_kyber.o $(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a $(KEXTRAS) -ldl -lkyber512_clean -lpthread

clean:
	rm -f *.o
