#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../lib/include/utilslib.h"

#define flush(stdin) while(getchar() != '\n')


int main(int argc, char const *argv[])
{	

	char options[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
	char op;
	char *filename;
	char *directory;
	char *dest_directory;
	char cwd[PATH_MAX];
	char final_directory[1024];
	char command[1024];
	mode_t mode = 0777;
	long result;
	int ret;
	int fd1;
	const char *home_dir = getenv("HOME");
	if (!home_dir) {
        printf("Home directory error\n");
        return -1;
    }

	if (!getcwd(cwd, sizeof(cwd))) {
        printf("Current working directory error\n");
        return -1;
    }



	while(true){

		printf("\033[2J\033[H");
		printf("\n\t**** OPERATIONS ****\n\n");
		printf("\t1) Open a file\n");
		printf("\t2) Delete a file\n");
		printf("\t3) Create a directory\n");
		printf("\t4) Delete a directory\n");
		printf("\t5) Move a file/directory\n");
		printf("\t6) Copy a file\n");
		printf("\t7) Copy a directory\n");
		printf("\t8) Link a file\n");
		printf("\t9) Quit\n\n");

		op = multiChoice("-> Select an option", options, 9);

		switch(op){

			case '1':

				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }

reinsert_open:	
				printf("Please insert the filename: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}


				fd1 = open(filename, O_WRONLY);
				if(fd1 == -1){
					printf("open error\n");
					fflush(stdout);
					flush(stdin);
					free(filename);
					goto reinsert_open;
				}

				printf("File OPENED correctly...\n");
				fflush(stdout);
				flush(stdin);
				close(fd1);
				free(filename);

				break;

			case '2':
				
				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }

reinsert_unlink:
				printf("Please insert the filename: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				ret = unlink(filename);
				if(ret != 0){
					printf("unlink error\n");
					fflush(stdout);
					flush(stdin);
					free(filename);
					goto reinsert_unlink;
				}

				printf("File REMOVED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(filename);

				break;

			case '3':

reinsert_mkdir:	
				memset(final_directory, 0, 1024);
				strcat(final_directory, home_dir);
				printf("Please specify the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				strcat(final_directory, dest_directory);

				if (chdir(final_directory) == -1) {
			        printf("Error while executing cd.\n");
			        fflush(stdout);
					flush(stdin);
					memset(final_directory, 0, 1024);
					free(dest_directory);
			        goto reinsert_mkdir;
			    }

			    printf("\nPWD: ");
			    fflush(stdout);
			    system("pwd");
			    

				printf("Please insert the directory name to create: ");

				ret = scanf("%ms", &directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				result = syscall(SYS_mkdir, directory, mode);
				if(result != 0){
					printf("syscall mkdir error\n");
					fflush(stdout);
					flush(stdin);
					memset(final_directory, 0, 1024);
					free(dest_directory);
					free(directory);
					goto reinsert_mkdir;
				}
			

				printf("Directory CREATED correctly...\n");
				fflush(stdout);
				flush(stdin);
				memset(final_directory, 0, 1024);
				free(dest_directory);
				free(directory);

				break;
				
			case '4':

				
reinsert_rmdir:	
				memset(final_directory, 0, 1024);
				strcat(final_directory, home_dir);
				printf("Please specify the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				strcat(final_directory, dest_directory);

				if (chdir(final_directory) == -1) {
			        printf("Error while executing cd.\n");
			        fflush(stdout);
					flush(stdin);
					memset(final_directory, 0, 1024);
					free(dest_directory);
			        goto reinsert_rmdir;
			    }

			    printf("\nPWD: ");
			    fflush(stdout);
			    system("pwd");
			    

				printf("Please insert the directory name to remove: ");

				ret = scanf("%ms", &directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				result = syscall(SYS_rmdir, directory);
				if(result != 0){
					printf("syscall rmdir error\n");
					fflush(stdout);
					flush(stdin);
					memset(final_directory, 0, 1024);
					free(dest_directory);
					free(directory);
					goto reinsert_rmdir;
				}
			

				printf("Directory REMOVED correctly...\n");
				fflush(stdout);
				flush(stdin);
				memset(final_directory, 0, 1024);
				free(dest_directory);
				free(directory);

				break;



			case '5':
				
				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }

				printf("Please insert the filename: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				printf("Please insert the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}



				sprintf(command, "mv %s %s", filename, dest_directory);
				ret = system(command);
				if(ret != 0){
					exit(1);
				}

				printf("File MOVED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(filename);
				free(dest_directory);
				memset(command, 0, 1024);

				break;

			case '6':
				
				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }
			    
				printf("Please insert the filename: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				printf("Please insert the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}



				sprintf(command, "cp %s %s", filename, dest_directory);
				ret = system(command);
				if(ret != 0){
					exit(1);
				}

				printf("File COPIED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(filename);
				free(dest_directory);
				memset(command, 0, 1024);

				break;

			case '7':
				
				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }
			    
				printf("Please insert the directory to copy: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				printf("Please insert the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}



				sprintf(command, "cp -r %s %s", filename, dest_directory);
				ret = system(command);
				if(ret != 0){
					exit(1);
				}

				printf("Directory COPIED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(filename);
				free(dest_directory);
				memset(command, 0, 1024);

				break;

			case '8':
				
				memset(final_directory, 0, 1024);
				strncpy(final_directory, cwd, 1024);

				if (chdir(final_directory) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }
			    
				printf("Please insert the filename: ");

				ret = scanf("%ms", &filename);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				printf("Please insert the destination directory: ");

				ret = scanf("%ms", &dest_directory);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}



				sprintf(command, "ln %s %s", filename, dest_directory);
				ret = system(command);
				if(ret != 0){
					exit(1);
				}

				printf("File LINKED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(filename);
				free(dest_directory);
				memset(command, 0, 1024);

				break;

			case '9':
				return 1;
				
			default:
				fprintf(stderr, "Invalid condition at %s: %d\n", __FILE__, __LINE__);
				abort();
		}

		printf("\npremere invio per continuare..\n");
		getchar();
	}
	
}