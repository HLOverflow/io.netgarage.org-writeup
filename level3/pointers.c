#include <stdio.h>

int main(){
	int a = 5;
	int b = 5;
	int * ptr = &a;
	printf("value of a: %d\n", a);
	printf("value of a: %d\n", *ptr);
	printf("value of b: %d\n", b);
	*ptr = 10;
	printf("value of a: %d\n", a);
	printf("value of a: %d\n", *ptr);
	printf("value of b: %d\n", b);
	return 0;
}
