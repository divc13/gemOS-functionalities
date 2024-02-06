#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>

int main(int argc, char* argv[])
{

	if (argc < 2){
		perror("Unable to execute\n");
		exit(1);
	}

	unsigned long num = atol(argv[argc - 1]);
	num = round(sqrtl(num));

	if (argc == 2){
		printf("%lu\n", num);
		exit(1);
	}

	char num_string[10];
	sprintf(num_string, "%lu", num);

	char *myArgs[argc];
	for(int i = 1;i < argc - 1;i++){
		myArgs[i - 1] = argv[i];
	}
	myArgs[argc - 2] = num_string;
	myArgs[argc - 1] = NULL;

	execv(myArgs[0], myArgs);

	perror("Unable to execute\n");
	return 0;
}