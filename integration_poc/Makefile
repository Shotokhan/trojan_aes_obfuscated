all: main

main: main.o pkcs7_padding.o aes.o
	gcc -m32 -z execstack -fno-stack-protector -o main main.o pkcs7_padding.o aes.o

main.o: main.c
	gcc -m32 -c main.c

pkcs7_padding.o: pkcs7_padding.c pkcs7_padding.h
	gcc -m32 -c pkcs7_padding.c

aes.o: aes.c aes.h aes.hpp
	gcc -m32 -c aes.c 
	
clean:
	rm -f *.o
	rm -f *.~
	rm -f ./main

