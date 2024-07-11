#ifndef _UTILPATH_

#define _UTILPATH_

char *get_absolute_path(int dir_fd, const char __user *filename);
char *get_absolute_path_dir(int dfd, const char *filename);
char *search_directory(char *path);
char *search_full_path(struct path path_struct);
char *get_full_path(const char *rel_path);
char *search_curdir(void);
unsigned long get_inode_number(char *path); 
struct inode *get_inode(char *path);
char *get_path_from_dentry(struct dentry *dentry);

#endif