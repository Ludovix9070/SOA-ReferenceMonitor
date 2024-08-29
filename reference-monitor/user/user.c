
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lib/include/syscall.h"
#include "lib/include/utilslib.h"

#define flush(stdin) while(getchar() != '\n')

int main(int argc, char** argv){
	
	char options[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
	char op;
	char *password;
	char *newpassword;
	char *path;
	int ret;

	while(true){

		printf("\033[2J\033[H");
		printf("\n\t**** REFERENCE MONITOR ****\n\n");
		printf("\t1) Set reference monitor STATUS to ON\n");
		printf("\t2) Set reference monitor STATUS to OFF\n");
		printf("\t3) Set reference monitor STATUS to REC-ON\n");
		printf("\t4) Set reference monitor STATUS to REC-OFF\n");
		printf("\t5) Add new path to the blacklist\n");
		printf("\t6) Remove path from the blacklist\n");
		printf("\t7) Change current PASSWORD\n");
		printf("\t8) Quit\n\n");

		op = multiChoice("-> Select an option", options, 8);

		switch(op){

			case '1':

reinsert_on:
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();
				if((ret = on(password)) < 0){
					printf("\nOperation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					goto reinsert_on;
				}	

				printf("\nReference STATUS set to ON correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(password);

				break;

			case '2':

reinsert_off:
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				if((ret = off(password)) < 0){
					printf("\nOperation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					goto reinsert_off;
				}		

				printf("\nReference STATUS set to OFF correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(password);

				break;

			case '3':
reinsert_recon:			
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				if((ret = rec_on(password)) < 0){
					printf("\nOperation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					goto reinsert_recon;
				}		

				printf("\nReference STATUS set to REC-ON correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(password);

				break;
				
			case '4':

reinsert_recoff:
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				if((ret = rec_off(password)) < 0){
					printf("\nOperation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					goto reinsert_recoff;
				}		

				printf("\nReference STATUS set to REC-OFF correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(password);

				break;

			case '5':
				
reinsert_addpath:			
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				printf("\nPlease insert the path: ");

				ret = scanf("%ms", &path);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}
				ret = add_path(path, password);
				if(ret == -1){
					printf("Operation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					free(path);
					goto reinsert_addpath;
				}else if(ret == 2){
					printf("Operation denied...\n");
					goto exit_add;
				}else if(ret == 0){
					printf("Path already blacklisted...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					free(path);
					break;
					
				}	

				printf("Path ADDED correctly to the BLACKLIST...\n");

exit_add:
				fflush(stdout);
				flush(stdin);
				free(password);
				free(path);

				break;
				
			case '6':
				
reinsert_rmpath:			
				printf("Please insert the password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				printf("\nPlease insert the path: ");

				ret = scanf("%ms", &path);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}
				ret = rm_path(path, password);
				if(ret == -1){
					printf("Operation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					free(path);
					goto reinsert_rmpath;
				}else if(ret == 2){
					printf("Operation denied...\n");
					goto exit_rm;
				}else if(ret == 0){
					printf("Path NOT present in blacklist...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					free(path);
					break;
					
				}		

				printf("Path REMOVED correctly from the BLACKLIST...\n");

exit_rm:
				fflush(stdout);
				flush(stdin);
				free(password);
				free(path);
				
				break;
			
			case '7':
				
reinsert_changepass:			
				printf("Please insert the old password: ");

				hide_input_mode();
				ret = scanf("%ms", &password);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}
				show_input_mode();

				printf("\nPlease insert the new password: ");

				hide_input_mode();
				ret = scanf("%ms", &newpassword);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}
				show_input_mode();
				if((ret = change_password(newpassword, password)) < 0){
					printf("\nOperation aborted, please retry...\n");
					fflush(stdout);
					flush(stdin);
					free(password);
					free(newpassword);
					goto reinsert_changepass;
				}		

				printf("\nPassword UPDATED correctly...\n");
				fflush(stdout);
				flush(stdin);
				free(password);
				free(newpassword);
				
				break;

			case '8':
				return 1;
			
			default:
				fprintf(stderr, "Invalid condition at %s: %d\n", __FILE__, __LINE__);
				abort();
		}

		printf("\npremere invio per continuare..\n");
		getchar();
	}
}
