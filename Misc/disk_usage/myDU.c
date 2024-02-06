#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

long long int SizeCalc(char* dir, int level){

	level++;

	DIR *dp = opendir(dir);
	if (dp == NULL)
	{
		perror("Unable to execute\n");
		exit(1);
	}

	struct dirent *d;
	struct stat s;
	long long int SZ_DIR = 0;

	while ((d = readdir(dp)) != NULL)
	{

		int len1 = strlen(dir);
		int len2 = strlen(d->d_name);
		char file_path[len1 + len2 + 2];

		for (int i = 0; i < len1; i++)
			file_path[i] = dir[i];

		file_path[len1] = '/';

		for (int i = 0; i < len2; i++)
			file_path[i + len1 + 1] = d->d_name[i];

		file_path[len1 + len2 + 1] = '\0';

		if (stat(file_path, &s) == -1)
		{
			perror("Unable to execute\n");
			exit(1);
		}

		if (S_ISREG(s.st_mode))
			SZ_DIR += s.st_size;

		else if (S_ISDIR(s.st_mode))
		{

			if(strcmp(d->d_name,".") == 0){
				SZ_DIR += s.st_size;
				continue;
			}

			if(strcmp(d->d_name , "..") == 0){
				continue;
			}

			int fd[2];
			char buf[20];
			if(pipe(fd) < 0){
				perror("Unable to execute\n");
				exit(1);
			}

			if(level == 1)
			{
				int rc = fork();

				if(rc < 0){
					perror("Unable to execute\n");
					exit(1);
				}

				if(rc == 0){
					long long size_subdr = SizeCalc(file_path, level);

					char num_str[20];
					sprintf(num_str, "%lld", size_subdr);

					if (write(fd[1], num_str, 20) != 20){
						perror("Unable to execute\n");
						exit(1);
					}
					exit(1);
				}

				else{

					if(read(fd[0], buf, 20) != 20){
						perror("Unable to execute\n");
						exit(1);
					}

					long long int size_subdr2 = atoll(buf);
					SZ_DIR += size_subdr2;
				}
			}

			else 
			{
				SZ_DIR += SizeCalc(file_path, level);
			}

		}

		else if(S_ISLNK(s.st_mode)){

			int sz_link = s.st_size;
			char target_lnk[sz_link + 1];

			ssize_t len = readlink(target_lnk, file_path, sz_link);
			if(len == -1){
				perror("Unable to execute\n");
				exit(1);
			}

			SZ_DIR += SizeCalc(target_lnk, level);
		}
	}

	closedir(dp);

	return SZ_DIR;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		perror("Unable to execute\n");
		exit(1);
	}

	char *dir = argv[1];
	int level = 0;
	long long sz = SizeCalc(dir, level);

	printf("%lld\n", sz);
}