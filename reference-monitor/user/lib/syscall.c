#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define LIBNAME "CSTMSYSCALLS"

int get_code(char *command){
	FILE *fp;
    char path[1035];
    int result;
 
    // Esegue il comando "cat example.txt" e apre una pipe per leggere l'output
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Impossibile eseguire il comando\n");
        return 1;
    }
 
    // Legge l'output una riga alla volta e lo stampa sullo schermo
    while (fgets(path, sizeof(path), fp) != NULL) {
        result = atoi(path);
    }
 
    // Chiude la pipe
    int status = pclose(fp);
    if (status == -1) {
        // Errore durante la chiusura della pipe
        perror("pclose");
        return 1;
    }
 
    return result;
}


long on(char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry0\""), password);
}

long off(char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry1\""), password);
}

long rec_on(char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry2\""), password);
}

long rec_off(char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry3\""), password);

}

long add_path(char *path, char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry4\""), path, password);

}

long rm_path(char *path, char *password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry5\""), path, password);

}

long change_password(char *new_password, char *old_password){
	return syscall(get_code("cat \"/sys/module/the_reference_monitor/parameters/entry6\""),new_password, old_password);

}