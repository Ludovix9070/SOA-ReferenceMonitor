#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>
#include <linux/path.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ludovico De Santis");
MODULE_DESCRIPTION("Path utility module");

#define LIBNAME "UTILPATH"

#define MAX_PATH_LEN 4096

struct nameidata {
    struct path path;           // Percorso del file/directory
    struct qstr last;           // Ultimo componente del percorso
    struct path root;           // Percorso della directory radice
    struct inode *inode;        // Nodo inode del file/directory
    unsigned int flags;         // Flags di stato
    struct dentry *dentry;      // Entry di directory corrente
    struct vfsmount *mnt;       // Mountpoint del percorso
    struct namespace *namespace; // Namespace del percorso
    unsigned seq;               // Sequenza di lookup
    int last_type;              // Tipo di ultima componente
    unsigned depth;             // Profondità del lookup
    struct saved *saved;        // Percorsi salvati
    struct path *base;          // Percorso di base (per le operazioni relative)
};


/*
* This function returns the absolute path of the "filename" file.
*/ 
char *get_absolute_path(int dir_fd, const char __user *filename){
	struct path path;
	int dfd=AT_FDCWD;
	char *abs_path=NULL;
	int error = -EINVAL,flag=0;
	unsigned int lookup_flags = 0;
	char *tpath=kmalloc(PATH_MAX,GFP_KERNEL);
	abs_path = kmalloc(PATH_MAX, GFP_KERNEL); // Allocazione di memoria per il percorso
	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) != 0)
	    goto out;
	if (!(flag & AT_SYMLINK_NOFOLLOW))
	    lookup_flags |= LOOKUP_FOLLOW;
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
	    goto out;
	abs_path = d_path(&path, tpath, PATH_MAX);
	return abs_path;

out:
	kfree(tpath);
	return NULL;
}

/*
* This function returns the absolute path of the "filename" directory.
*/ 
char *get_absolute_path_dir(int dfd, const char *filename) {
    struct path path;
    char *abs_path = NULL;

    if (kern_path(filename, dfd, &path) == 0) {
        abs_path = kmalloc(PATH_MAX, GFP_KERNEL); 
        if (abs_path != NULL) {
            abs_path = d_path(&path, abs_path, PATH_MAX);
            return abs_path; 
        }
    }

    return NULL;
}

/*
* This function extracts the directory from the input path.
*/ 
char *search_directory(char *path){

	int i= strlen(path)-1;
	char *dir = kmalloc(strlen(path), GFP_KERNEL);
	if(dir == NULL)  return "";
	
	while(i>=0){
		if(path[i] != '/'){ 
			dir[i] = '\0'; 
		}
		else{
			dir[i]='\0';
			i--;
		 	break;
		}
		i--;
	}
	
	while(i>=0){
		dir[i] = path[i];
		i--;
	}
	
	return dir;
}

/*
* This function returns the entire path.
*/ 
char *search_full_path(struct path path_struct){
	char *tmp_path;
	char *path;
	
	tmp_path=kmalloc(1024,GFP_KERNEL);
	if(tmp_path == NULL)  return "";
	path = d_path(&path_struct, tmp_path, 1024);
	
	return path;
}

/*
* This function returns the entire path from relative path
*/
char *get_full_path(const char *rel_path) {

	char *k_full_path, *rel_path_tilde, *tilde_pos;
	struct path path;
	int ret;

    if (rel_path[0] == '/') {
        k_full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!k_full_path) {
                pr_err("Error in kmalloc (get_full_path)\n");
                return NULL; 
        }

        strcpy(k_full_path, rel_path);
        //return (char *)rel_path;
        return k_full_path;
    }


    k_full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!k_full_path) {
            pr_err("Error in kmalloc (get_full_path)\n");
            return NULL; 
    }

    ret = kern_path(rel_path, LOOKUP_FOLLOW, &path);
    if (ret == -ENOENT) {
            rel_path_tilde = kmalloc(PATH_MAX, GFP_KERNEL);
            if (!rel_path_tilde) {
                    pr_err("Error in kmalloc (rel_path_tilde)\n");
                    return NULL; 
            }

            strcpy(rel_path_tilde, rel_path);
            strcat(rel_path_tilde, "~");

            ret = kern_path(rel_path_tilde, LOOKUP_FOLLOW, &path);

            kfree(rel_path_tilde);
    }
    if (ret) {
            pr_info("Full path not found (error %d) for file %s\n", ret, rel_path);
            kfree(k_full_path);
            return NULL;
    }

    ret = snprintf(k_full_path, PATH_MAX, "%s", d_path(&path, k_full_path, PATH_MAX));
    if (ret < 0 || ret >= PATH_MAX) {
            kfree(k_full_path);
            pr_err("Full path is too long\n");
            return NULL;
    }

    tilde_pos = strrchr(k_full_path, '~');
    if (tilde_pos != NULL) {
            *tilde_pos = '\0'; 
    }

    return k_full_path;
}

/*
* This function returns the current directory.
*/ 
char *search_curdir(void){

	struct path abs_path;
    char *buffer;
    char *curdir;
    long error_code;

	buffer = kmalloc(1024,GFP_KERNEL);
	if(buffer == NULL) return "";

	get_fs_pwd(current->fs, &abs_path);

	curdir = dentry_path_raw(abs_path.dentry, buffer, PATH_MAX);
    if (IS_ERR(curdir)) {
        error_code = PTR_ERR(curdir);
        //printk(KERN_ERR "Errore nel convertire la dentry in un percorso: %ld\n", error_code);
        kfree(buffer);
        return "";
    } else {
        //printk(KERN_INFO "Il percorso del file è: %s\n", curdir);
        return curdir;
    }
	
	//return curdir;

}

/*
* This function returns the requested path's inode number.
*/
unsigned long get_inode_number(char *path) {

        struct path lookup_path;
        struct inode *inode;

        if (kern_path(path, 0, &lookup_path) != 0) {
                printk("Failed to lookup path %s\n", path);
                return -1;
        }

        inode = lookup_path.dentry->d_inode;

        return inode->i_ino;

}

/*
* This function returns the requested path's inode.
*/
struct inode *get_inode(char *path) {

    struct path lookup_path;
    struct inode *inode;


    if (kern_path(path, 0, &lookup_path) != 0) {
            printk("Failed to lookup path %s\n", path);
            return NULL;
    }

    inode = lookup_path.dentry->d_inode;

    return inode;

}

/*
* This function returns the absolute path starting from its dentry.
*/
char *get_path_from_dentry(struct dentry *dentry) {

	char *buffer, *full_path;

    buffer = (char *)__get_free_page(GFP_KERNEL);
    if (!buffer)
            return NULL;

    full_path = dentry_path_raw(dentry, buffer, PATH_MAX);
    if (IS_ERR(full_path)) {
            printk("dentry_path_raw failed: %li", PTR_ERR(full_path));
            free_page((unsigned long)buffer);
            return NULL;
    } 


    free_page((unsigned long)buffer);
    return full_path;
}


