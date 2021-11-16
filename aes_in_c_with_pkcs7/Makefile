all: main

main: main.o pkcs7_padding.o aes.o
	gcc -o main main.o pkcs7_padding.o aes.o

main.o: main.c
	gcc -c main.c

pkcs7.o: pkcs7_padding.c pkcs7_padding.h
	gcc -c pkcs7_padding.c

aes.o: aes.c aes.h aes.hpp
	gcc -c aes.c 
	
clean:
	rm -f *.o
	rm -f *.~
	rm -f ./main

