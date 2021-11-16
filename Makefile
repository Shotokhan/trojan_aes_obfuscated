all:
	gcc execute_poc_m32.c -m32 -z execstack -fno-stack-protector -o execute_poc_m32 

clean:
	rm -f ./execute_poc_m32
