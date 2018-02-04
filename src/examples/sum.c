//num1을 parameter로 하여 pibonacci를 수행하고 num 1, 2, 3, 4를 parameter로 하여 sumoffourinteger 를 수행한 후 결과를 출력한다. ./sum 5 5 1 4하면 

#include<stdio.h>
#include<stdlib.h>
#include<syscall.h>

int main (int argc, char* argv[]){

		int a,b,c,d;

		a = atoi(argv[1]);
		b = atoi(argv[2]);
		c = atoi(argv[3]);
		d = atoi(argv[4]);


		printf("%d %d\n",pibonacci(a),sum_of_four_integers(a,b,c,d));

		return EXIT_SUCCESS;



}

