#ifndef _CSTMSYSCALLS_

#define _CSTMSYSCALLS_

int get_code(char *command);
long on(char *password);
long off(char *password);
long rec_on(char *password);
long rec_off(char *password);
long add_path(char *path, char *password);
long rm_path(char *path, char *password);
long change_password(char *new_password, char *old_password);


#endif 
