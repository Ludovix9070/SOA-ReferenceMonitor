/**		      
* This is free software; 
* You can redistribute it and/or modify this file under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This file is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @brief This is a simple Linux Kernel Module which implements
*	 a mandatory policy for the {do_filp_open, do_unlinkat, do_mkdirat, do_rmdir} services, 
* 	 closing it to all the users of the system (including root user) for a 
*	 black list of files/directories paths.
*
* @author Ludovico De Santis
*
* @date April 9, 2024
*
*/

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
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <generated/utsrelease.h> 
#include <linux/rcupdate.h>
#include "lib/include/utilcrypto.h"
#include "lib/include/utilpath.h"
#include "lib/include/scth.h"
#include "include/reference_monitor.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ludovico De Santis");
MODULE_DESCRIPTION("see the README file");

unsigned long the_syscall_table = 0x0;
int entry0=0;
int entry1=0;
int entry2=0;
int entry3=0;
int entry4=0;
int entry5=0;
int entry6=0;

char *the_file;
char *the_path;
module_param(the_syscall_table, ulong, 0660);
module_param(the_file, charp, 0660);
module_param(the_path, charp, 0660);
module_param(entry0, int, 0660);
module_param(entry1, int, 0660);
module_param(entry2, int, 0660);
module_param(entry3, int, 0660);
module_param(entry4, int, 0660);
module_param(entry5, int, 0660);
module_param(entry6, int, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[7];

#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
char default_pass[32] = "password\0";
t_monitor ref_monitor;


/*
* Deferred Work: function to write on log-file informations about denied operations by the reference monitor.
*/
void deferred_write(unsigned long input){

	ssize_t bytes_read;
	unsigned char hash[HASH_SIZE];
	char *hash_to_write;
	char *buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	char *line = kzalloc(4096, GFP_KERNEL);
	packed_work *data = (void*)container_of((void*)input,packed_work,the_work);
	struct file *output_file = NULL;
	struct file *input_file = NULL;

	if(data->command_path == NULL)  return;
	
	input_file = filp_open(data->command_path, O_RDONLY , 0);
	if (IS_ERR(input_file)) {
		printk("%s Input file opening error\n", MODNAME);
    		return;
	}

	output_file = filp_open(the_file, O_WRONLY, 0);
	if (IS_ERR(output_file)) {
		printk("%s Impossible to open the log-file\n", MODNAME);
    		goto close_input;
	}

	if(buffer == NULL || line == NULL) goto close_output;

	sprintf(line, "TGID: %d PID: %d UID: %d EUID: %d Program name: %s Hash exe file content:", data->tgid, data->pid, data->uid, data->euid, data->command_path);
	while ((bytes_read = kernel_read(input_file, buffer, BUFFER_SIZE, &input_file->f_pos)) > 0) {
	        hash_to_write = calculate_sha256(buffer, bytes_read, hash);
	        if (hash_to_write == NULL) {
	            pr_err("Failed to compute SHA256\n");
	            goto free_buffer;
        	}

       		sprintf(line+strlen(line),"%s", hash_to_write);
	
	}
    
    	sprintf(line+strlen(line),"\n");
	
	// Scrivi l'hash sul file di output
	kernel_write(output_file, line, strlen(line), &output_file->f_pos);
	
	printk("%s Log-file correctly updated\n", MODNAME);

free_buffer: 
	kfree(buffer);
	kfree(line);

close_output:
	filp_close(output_file, NULL);

close_input:
	filp_close(input_file, NULL);

	return;
	
}


/*
* Wrapper to deny open operation in write mode on blacklisted files. 
*/
static int do_filp_open_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	// struct file* do_filp_open(int dfd, struct filename * pathname, const struct open_flags *op);
	int i;
	packed_work *the_task;

	char *path;
	char *dir_path = NULL;
	char *cmd_path;
	char *dir;
	char *path_to_check = NULL;
	int is_cp = 0;
	int step = 0;
	unsigned long inode_number;
	struct inode *inode;
	struct dentry *dentry;
	struct hlist_head *dentry_head;
	
	//int dfd = (int)(regs->di);
	const __user char *user_path = ((struct filename *)(regs->si))->uptr;
	const struct open_flags *opf = (struct open_flags *)(regs->dx);
	const char *actual_path = ((struct filename *)(regs->si))->name;
	int flags = opf->open_flag;
	

	//skipping /run checks
	char tmp_path[5]; 
	strncpy(tmp_path, actual_path, 4);
	tmp_path[4]='\0';
	if(strcmp(tmp_path, "/run") == 0){
		 return 0;
	}

	if(!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL ))){
		if(strcmp(current->comm,"cp\0") != 0){
			return 0;
		}
		is_cp = 1;
		printk("%s:cp in (only) read mode intercepted\n", MODNAME);
	}

	if(strcmp(current->comm,"cp\0") == 0){
		is_cp = 1;
	}
	
	if(user_path == NULL){
		if(actual_path == NULL){
			goto reject_do_filp_open;
		}
		path = (char *)actual_path;
	}else{
		path = get_full_path(user_path);
		if(path == NULL){
			if(actual_path == NULL){
				goto reject_do_filp_open;
			}
		 	path = (char *)actual_path;
		}
	}


	if(strcmp(path, "") == 0 || strcmp(path, " ") == 0){
		printk("RETURNING for empty path\n");
		return 0;
	}
	
	dir = search_directory(path);
	if(strcmp(dir, "") == 0) dir = search_curdir();
		
	printk("%s: File (with flags %d) %s opening in %s directory occurred by %s\n",MODNAME, flags, path, dir, current->comm);

reinode:	
	inode = get_inode(path);
    if (inode == NULL) {
        printk(KERN_INFO "Inode non valido\n");
        if(is_cp && (dir_path == NULL)){
        	if(step != 0){
   				printk("%s: returning..",MODNAME);
        		return 0;
        	}
        	step++;
        	dir_path = get_full_path(dir);
        	if(dir_path != NULL){
        		memset(path, 0, PATH_MAX);
        		strcpy(path, dir_path);
        	}
        	goto reinode;
        }

        return 0;
    }

    inode_number = inode->i_ino;

    if(inode->i_nlink > 1){

    	/* handling of links */
    	dentry_head = &inode->i_dentry;

    	if(dentry_head){
		    hlist_for_each_entry_rcu(dentry, dentry_head, d_u.d_alias) {

		        if(dentry && dentry->d_inode){
		        	path_to_check = get_path_from_dentry(dentry);
		        }

		    	if(path_to_check  == NULL){
		    		printk(KERN_INFO "Path to check null\n");
        			return 0;
		    	}
		    	printk("%s: path_to_check is %s", MODNAME, path_to_check);
			

				for(i=0; i<ref_monitor.list_size ; i++){

					/*blocks directly opening of hardlinks already created on blacklisted files*/
					if(inode_number == get_inode_number(ref_monitor.path[i])){
						printk("%s: File %s (path_to_check is %s) content cannot be modified through direct hardlinks. Operation denied\n",MODNAME, path, path_to_check);
						goto reject_do_filp_open;
					}

					/*blocks directly opening of hardlinks already created on blacklisted files
					  working also with hardlinks to file in blacklisted directories
					  and cp with a blacklisted directory (or sub) as destination*/
					if(strstr(path_to_check, ref_monitor.path[i]) != NULL && strncmp(path_to_check, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
						printk("%s: File %s (path_to_check is %s) content cannot be modified. Operation denied\n",MODNAME, path, path_to_check);
						goto reject_do_filp_open;
					}

					/*blocks symlinks opening avoiding cycles*/
					if(strstr(path, ref_monitor.path[i]) != NULL && strncmp(path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
						printk("%s: File %s content cannot be modified through symlinks. Operation denied\n",MODNAME, path);
						goto reject_do_filp_open;
					}

				}

			}
		}	

	}else{
		for(i=0; i<ref_monitor.list_size ; i++){

			/*blocks normal file openings and copying out blacklisted files or files in blacklisted directories*/
			if(strstr(path, ref_monitor.path[i]) != NULL && strncmp(path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){	
				printk("%s: File %s content cannot be modified. Operation denied\n",MODNAME, path);
				goto reject_do_filp_open;
			}

		}

	}

	return 0;

reject_do_filp_open:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->di = -1;
	regs->si = (unsigned long)NULL;
		
	return 0;
}


/*
* Wrapper to deny mkdir operation in blacklisted directories. 
*/
static int do_mkdirat_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	//int do_mkdirat(int dfd, struct filename *name, umode_t mode)
	int i;
	packed_work *the_task;

	char *path;
	char *cmd_path;
	char *dir;
	char *dirdir;
	
	int dfd = (int)(regs->di);
	struct filename *name = (struct filename *)(regs->si);
	const __user char *user_path = name->uptr; 
	const char *actual_path = name->name;
	
	if(user_path == NULL){
		path = (char *)actual_path;
	}else{
		path = get_absolute_path_dir(dfd, user_path);
		if(path == NULL) {
			path = (char *)actual_path;
		}
	}
	
	dirdir = search_directory(path);
	dir = get_full_path(dirdir);
	if(dir == NULL) {
		dir = search_curdir();
	}

	printk("%s: Directory %s creation in %s directory occurred\n",MODNAME, path, dir);
	
	for(i=0; i<ref_monitor.list_size; i++){
		/*blocks mkdir and dir cp (cp -r) on blacklisted directories */
		if(strstr(dir, ref_monitor.path[i]) != NULL && strncmp(dir, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: Directory %s content cannot be created. Operation denied\n",MODNAME, dir);
			goto reject_do_mkdirat;
		}
	}

	return 0;

reject_do_mkdirat:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->si = (unsigned long)NULL;
	
	return 0;
}


/*
* Wrapper to deny rmdir operation on blacklisted directories. 
*/
static int do_rmdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	//int do_rmdir(int dfd, struct filename *name)
	int i;
	packed_work *the_task;

	char *path;
	char *cmd_path;
	char *dir;
	char *dirdir;
	
	int dfd = (int)(regs->di); 
	struct filename *name = (struct filename *)(regs->si); 
	const __user char *user_path = name->uptr; 
	const char *actual_path = name->name;
	 
	if(user_path == NULL){
		path = (char *)actual_path;
	}else{
		path = get_absolute_path_dir(dfd, user_path);
		if(path == NULL){
			path = (char *)actual_path;
		}
	}
	
	dirdir = search_directory(path);
	dir = get_full_path(dirdir);
	if(dir == NULL){
		dir = search_curdir();
	}

	printk("%s: Directory %s deletion in %s directory occurred\n",MODNAME, path, dir);

	for(i=0; i<ref_monitor.list_size; i++){

		if(strstr(path, ref_monitor.path[i]) != NULL && strncmp(path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: Directory %s cannot be removed. Operation denied\n",MODNAME, path);
			goto reject_do_rmdir;
		}
	}

	return 0;

reject_do_rmdir:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->si = (unsigned long)NULL;
	
	return 0;
}


/*
* Wrapper to deny remove operation on blacklisted files. 
*/
static int do_unlinkat_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	//int do_unlinkat(int dfd, struct filename *name)
	int i;
	packed_work *the_task;

	char *path;
	char *cmd_path;
	char *dir;
	
	//int dfd = (int)(regs->di); 
	struct filename *name = (struct filename *)(regs->si);
	const __user char *user_path = name->uptr; 
	const char *actual_path = name->name;
	 
	if(user_path == NULL){
		path = (char *)actual_path;
	}else{
		path = get_full_path(user_path);
		if(path == NULL) {
			path = (char *)actual_path;
		}
	}
	
	dir = search_directory(path);
	if(strcmp(dir, "") == 0) dir = search_curdir();

	printk("%s: File %s deletion in %s directory occurred\n",MODNAME, path, dir);
	
	for(i=0; i<ref_monitor.list_size ; i++){

		if(strstr(path, ref_monitor.path[i]) != NULL && strncmp(path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: File %s content cannot be removed. Remove operation denied.\n",MODNAME, path);
			goto reject_do_unlinkat;
		}
	}

	return 0;

reject_do_unlinkat:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	
	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->si = (unsigned long)NULL;
	
	return 0;
}

/*
* Wrapper to deny mv operation on blacklisted files. 
*/
static int do_renameat2_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	//int do_renameat2(int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags)
	int i;
	packed_work *the_task;

	char *f_path;
	char *cmd_path;
	char *f_dir;
	char *dest_path;
	
	//int dfd = (int)(regs->di); 
	struct filename *from = (struct filename *)(regs->si);
	const __user char *from_path = from->uptr; 
	const char *actual_from_path = from->name;

	struct filename *to = (struct filename *)(regs->cx);
	const __user char *to_path = to->uptr; 
	const char *actual_to_path = to->name;

	if(from_path == NULL){
		f_path = (char *)actual_from_path;
	}else{
		f_path = get_full_path(from_path);
		if(f_path == NULL){
			f_path = (char *)actual_from_path;
		}
	}

	if(to_path == NULL){
		dest_path = (char *)actual_to_path;
	}else{
		dest_path = get_full_path(to_path);
		if(dest_path == NULL) {
			dest_path = (char *)actual_to_path;
		}
	}

	f_dir = search_directory(f_path);
	if(strcmp(f_dir, "") == 0) f_dir = search_curdir();

	printk("%s: Move %s intercepted in %s directory occurred with directory %s as destination\n",MODNAME, f_path, f_dir, dest_path);
	
	for(i=0; i<ref_monitor.list_size ; i++){

		if(strstr(dest_path, ref_monitor.path[i]) != NULL && strncmp(dest_path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: Directory %s content cannot be added. Move operation for file %s denied\n",MODNAME, dest_path, f_path);
			goto reject_do_renameat2;
		}

		if(strstr(f_path, ref_monitor.path[i]) != NULL && strncmp(f_path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: File %s content cannot be moved. Move operation denied.\n",MODNAME, f_path);
			goto reject_do_renameat2;
		}
	}

	return 0;

reject_do_renameat2:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	
	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->di = -1;
	regs->si = (unsigned long)NULL;
	//regs->dx = -1;
	
	return 0;
}

static int do_linkat_wrapper(struct kprobe *ri, struct pt_regs *regs){
	
	//int do_linkat(int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
	int i;
	packed_work *the_task;

	char *o_path;
	char *cmd_path;
	char *o_dir;
	char *dest_path;
	
	//int olddfd = (int)(regs->di); 
	struct filename *old = (struct filename *)(regs->si);
	const __user char *old_path = old->uptr; 
	const char *actual_old_path = old->name;

	struct filename *new = (struct filename *)(regs->cx);
	const __user char *new_path = new->uptr; 
	const char *actual_new_path = new->name;

	if(old_path == NULL){
		o_path = (char *)actual_old_path;
	}else{
		o_path = get_full_path(old_path);
		if(o_path == NULL) {
			o_path = (char *)actual_old_path;
		}
	}

	if(new_path == NULL){
		dest_path = (char *)actual_new_path;
	}else{
		dest_path = get_full_path(new_path);
		if(dest_path == NULL){
			dest_path = (char *)actual_new_path;
		}
	}

	o_dir = search_directory(o_path);
	if(strcmp(o_dir, "") == 0) o_dir = search_curdir();

	printk("%s: Hardlink of file %s intercepted in %s directory occurred with file %s as destination\n",MODNAME, o_path, o_dir, dest_path);
	
	for(i=0; i<ref_monitor.list_size ; i++){

		if(strstr(dest_path, ref_monitor.path[i]) != NULL && strncmp(dest_path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: File/Directory %s content cannot be linked. Link operation for file/directory %s denied\n",MODNAME, dest_path, o_path);
			goto reject_do_linkat;
		}

		if(strstr(o_path, ref_monitor.path[i]) != NULL && strncmp(o_path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){
			printk("%s: File %s content cannot be linked. Link operation denied.\n",MODNAME, o_path);
			goto reject_do_linkat;
		}

	}

	return 0;

reject_do_linkat:

	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	cmd_path = search_full_path(current->mm->exe_file->f_path);
	strncpy(the_task->command_path, cmd_path, strlen(cmd_path));
	strncpy(the_task->command, current->comm, strlen(current->comm));

	
	__INIT_WORK(&(the_task->the_work),(void*)deferred_write, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

	regs->si = (unsigned long)NULL;
	
	return 0;
}


static struct kprobe kp_do_filp_open = {
        .symbol_name = "do_filp_open",
        .pre_handler = do_filp_open_wrapper,
};

static struct kprobe kp_do_mkdirat = {
        .symbol_name =  "do_mkdirat",
        .pre_handler = do_mkdirat_wrapper,
};

static struct kprobe kp_do_rmdir = {
        .symbol_name =  "do_rmdir",
        .pre_handler = do_rmdir_wrapper,
};

static struct kprobe kp_do_unlinkat = {
        .symbol_name =  "do_unlinkat",
        .pre_handler = do_unlinkat_wrapper,
};

static struct kprobe kp_do_renameat2 = {
        .symbol_name =  "do_renameat2",
        .pre_handler = do_renameat2_wrapper,
};

static struct kprobe kp_do_linkat = {
        .symbol_name =  "do_linkat",
        .pre_handler = do_linkat_wrapper,
};

/*
******SYSCALLS******
* sys_ref_mon_on: changes status to on.
* sys_ref_mon_off: changes status to off.
* sys_ref_mon_rec_on: changes status to rec-on.
* sys_ref_mon_rec_off: changes status to rec_off.
* sys_ref_mon_add_path: adds a path to blacklist.
* sys_ref_mon_rm_path: removes a path from blacklist.
* sys_ref_mon_change_pass: allows to change password.

* All syscalls are executed only with euid set to zero
* and an authentication password is required.
*/


/*
* This syscall takes in input the password and set the reference monitor to on.
* Probes are enabled and accesses to files/directories are intercepted.
* In particular, accesses to blacklisted files or operations 
* in blacklisted directories are rejected.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _ref_mon_on, char *, password){
#else
asmlinkage long sys_ref_mon_on(char *password){
#endif

	char *enc_pass;
	char *input_pass;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to set reference monitor STATUS to ON - PASS:%s\n",MODNAME, password);
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || strcmp(ref_monitor.pass, enc_pass) != 0){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}
	
	switch(ref_monitor.status) {
	
		case ON:
			break;
		case OFF:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
		case RECON:
		 	break;
		case RECOFF:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
		default:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
	
	}

	ref_monitor.status = ON;
	kfree(enc_pass);
	kfree(input_pass);
	spin_unlock(&ref_monitor.lock);

	printk("%s: Reference monitor STATUS set to ON\n", MODNAME);

	return 0;
	
}

/*
* This syscall takes in input the password and set the reference monitor to off.
* Probes are disabled and accesses to files/directories are not anymore intercepted.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _ref_mon_off, char *, password){
#else
asmlinkage long sys_ref_mon_off(char *password){
#endif

	char *enc_pass;
	char *input_pass;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to set reference monitor STATUS to OFF - PASS: %s\n",MODNAME, password);
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || strcmp(ref_monitor.pass, enc_pass) != 0){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}
	
	switch(ref_monitor.status) {
	
		case ON:
			disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
			break;
		case OFF:
		 	break;
		case RECON:
			disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
		 	break;
		case RECOFF:
		 	break;
		default:
		 	disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
		 	break;
	
	}

	ref_monitor.status = OFF;
	kfree(enc_pass);
	kfree(input_pass);
	spin_unlock(&ref_monitor.lock);

	printk("%s: Reference monitor STATUS set to OFF\n", MODNAME);

	return 0;
	
}

/*
* This syscall takes in input the password and set the reference monitor to rec-on.
* Probes are enabled and accesses to files/directories are intercepted.
* In particular, accesses to blacklisted files or operations 
* in blacklisted directories are rejected. It's moreover possible to reconfigure
* the blacklisted paths. In particular, it's possible to remove/add paths from/to 
* the blacklist. 
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _ref_mon_rec_on, char *, password){
#else
asmlinkage long sys_ref_mon_rec_on(char *password){
#endif

	char *enc_pass;
	char *input_pass;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to set reference monitor STATUS to REC-ON - PASS: %s\n",MODNAME, password);
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || (strcmp(ref_monitor.pass, enc_pass) != 0)){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}
	
	switch(ref_monitor.status) {
	
		case ON:
			break;
		case OFF:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
		case RECON:
		 	break;
		case RECOFF:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
		default:
		 	enable_kprobe(&kp_do_filp_open);
		 	enable_kprobe(&kp_do_unlinkat);
		 	enable_kprobe(&kp_do_mkdirat);
		 	enable_kprobe(&kp_do_rmdir);
		 	enable_kprobe(&kp_do_renameat2);
		 	enable_kprobe(&kp_do_linkat);
		 	break;
	
	}

	ref_monitor.status = RECON;
	kfree(enc_pass);
	kfree(input_pass);
	spin_unlock(&ref_monitor.lock);
	
	printk("%s: Reference monitor STATUS set to REC-ON\n", MODNAME);

	return 0;
	
}

/*
* This syscall takes in input the password and set the reference monitor to rec-off.
* Probes are enabled and accesses to files/directories are not anymore intercepted.
* It's moreover possible to reconfigure the blacklisted paths. 
* In particular, it's possible to remove/add paths from/to the blacklist. 
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _ref_mon_rec_off, char *, password){
#else
asmlinkage long sys_ref_mon_rec_off(char *password){
#endif

	char *enc_pass;
	char *input_pass;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to set reference monitor STATUS to REC-OFF Password %s\n",MODNAME, password);
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || (strcmp(ref_monitor.pass, enc_pass) != 0)){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}
	
	switch(ref_monitor.status) {
	
		case ON:
			disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
			break;
		case OFF:
		 	break;
		case RECON:
			disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
		 	break;
		case RECOFF:
		 	break;
		default:
		 	disable_kprobe(&kp_do_filp_open);
		 	disable_kprobe(&kp_do_unlinkat);
		 	disable_kprobe(&kp_do_mkdirat);
		 	disable_kprobe(&kp_do_rmdir);
		 	disable_kprobe(&kp_do_renameat2);
		 	disable_kprobe(&kp_do_linkat);
		 	break;
	
	}

	ref_monitor.status = RECOFF;
	kfree(enc_pass);
	kfree(input_pass);
	spin_unlock(&ref_monitor.lock);
	
	printk("%s: Reference monitor STATUS set to REC-OFF\n", MODNAME);

	return 0;
	
}

/*
* This syscall takes in input the password and a file/directory path
* to add a new path to blacklist.
* This operation is possible only in rec-on/off status.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _ref_mon_add_path, char*, new_path, char *, password){
#else
asmlinkage long sys_ref_mon_add_path(char *new_path, char *password){
#endif

	int i;
	char *abs_path;
	char *input_path;
	char *enc_pass;
	char *input_pass;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to ADD new path [%s] to BLACKLIST\n",MODNAME, new_path);
	}

	if((input_path = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_path, new_path, strnlen_user(new_path, PAGE_SIZE))) != 0){
		kfree(input_path);
		return -1;
	}

	abs_path = get_full_path(input_path);
	if(abs_path == NULL){
		printk("get_full_path error\n");
		kfree(input_path);
		return -1;
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			kfree(input_path);
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		kfree(input_path);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		kfree(input_path);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || (strcmp(ref_monitor.pass, enc_pass) != 0)){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(input_path);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}

	if(abs_path != NULL && strstr(abs_path, "/singlefile-FS/mount/the-file") != NULL ){
		printk("%s: Log-file excluded from checks\n", MODNAME);
		kfree(input_pass);
		kfree(enc_pass);
		kfree(input_path);
		spin_unlock(&(ref_monitor.lock));
		return -1;
	}

	if(ref_monitor.status == ON || ref_monitor.status == OFF){
		printk("%s: STATUS ON || OFF\n", MODNAME);
		kfree(input_pass);
		kfree(input_path);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
		return 2;
	}

	if(ref_monitor.list_size == MAXSIZE-1){
		printk("%s: Blacklist is filled\n", MODNAME);
		kfree(input_pass);
		kfree(input_path);
		kfree(enc_pass);
		spin_unlock(&(ref_monitor.lock));
		return 2;
	}
	
	for(i=0; i<ref_monitor.list_size; i++){
		if( strcmp(ref_monitor.path[i], abs_path) == 0 ){
			printk("%s: Filepath already present\n", MODNAME);
			kfree(input_pass);
			kfree(input_path);
			kfree(enc_pass);
			spin_unlock(&ref_monitor.lock);
			return 0;
		}
	} 
	
	ref_monitor.path[ref_monitor.list_size]= abs_path;
	ref_monitor.list_size++;
	kfree(enc_pass);
	kfree(input_pass);
	kfree(input_path);
	spin_unlock(&ref_monitor.lock);
	printk("%s: Path [%s] blacklisted correctly\n", MODNAME, abs_path);

	return 1;
	
}

/*
* This syscall takes in input the password and a file/directory path
* to remove from blacklist.
* This operation is possible only in rec-on/off status.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _ref_mon_rm_path, char *, path, char *, password){
#else
asmlinkage long sys_ref_mon_rm_path(char *path, char *password){
#endif

	char *enc_pass;
	char *abs_path;
	char *input_pass;
	char *input_path;
	int i;
	int j;

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to REMOVE path [%s] from the BLACKLIST %s\n",MODNAME, path, password);
	}

	if((input_path = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((copy_from_user(input_path, path, strnlen_user(path, PAGE_SIZE))) != 0){
		kfree(input_path);
		return -1;
	}
	
	abs_path = get_full_path(input_path);
	if(abs_path == NULL){
		printk("get_full_path error\n");
		kfree(input_path);
		return -1;
	}

	if((input_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			kfree(input_path);
			return -1;
	}

	if((copy_from_user(input_pass, password, strnlen_user(password, PAGE_SIZE))) != 0){
		kfree(input_pass);
		kfree(input_path);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_pass = encrypt_password(input_pass, ref_monitor.salt);
	if(enc_pass == NULL){
		printk("crypt error\n");
		kfree(input_pass);
		kfree(input_path);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || (strcmp(ref_monitor.pass, enc_pass) != 0)){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(input_pass);
		kfree(input_path);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}

	if(ref_monitor.status == ON || ref_monitor.status == OFF){
		printk("%s: STATUS ON || OFF\n", MODNAME);
		kfree(input_pass);
		kfree(input_path);
		kfree(enc_pass);
		spin_unlock(&ref_monitor.lock);
		return 2;
	}

	for(i=0; i<ref_monitor.list_size; i++){
		if(strcmp(ref_monitor.path[i], abs_path) == 0 ){
			if((j==0 && ref_monitor.list_size ==0) || j==MAXSIZE-1){
				ref_monitor.path[j]= NULL;
			}else{
				for(j=i; j<ref_monitor.list_size-1 ; j++){
					ref_monitor.path[j] = ref_monitor.path[j+1];
				}
			}
			ref_monitor.list_size--;
			kfree(enc_pass);
			kfree(input_pass);
			kfree(input_path);
			spin_unlock(&ref_monitor.lock);
			printk("%s: Path [%s] removed correctly\n", MODNAME, abs_path);
			return 1;
		}
	} 

	kfree(enc_pass);
	kfree(input_pass);
	kfree(input_path);
	spin_unlock(&ref_monitor.lock);
	printk("%s: Path [%s] not currently inserted in blacklist\n", MODNAME, abs_path);

	return 0;
	
}

/*
* This syscall allows to change reference monitor's password.
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _ref_mon_change_pass, char *, new_pass, char *, old_pass){
#else
asmlinkage long sys_ref_mon_change_pass(char *new_pass, char *old_pass){
#endif

	char *enc_new_pass;
	char *enc_old_pass;
	char *input_old_pass;
	char *input_new_pass;
	unsigned char salt[SALT_LENGTH];

	AUDIT{
		printk("%s: ------------------------------\n",MODNAME);
		printk("%s: Asked to CHANGE the PASSWORD - NEW PASS: %s - OLD PASS: %s\n",MODNAME, new_pass, old_pass);
	}

	if((input_old_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
	}

	if((input_new_pass = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			kfree(input_old_pass);
			return -1;
	}

	if((copy_from_user(input_new_pass, new_pass, strnlen_user(new_pass, PAGE_SIZE))) != 0){
		kfree(input_new_pass);
		kfree(input_old_pass);
		return -1;
	}

	if((copy_from_user(input_old_pass, old_pass, strnlen_user(old_pass, PAGE_SIZE))) != 0){
		kfree(input_new_pass);
		kfree(input_old_pass);
		return -1;
	}

	spin_lock(&ref_monitor.lock);

	enc_old_pass = encrypt_password(input_old_pass, ref_monitor.salt);
	if(enc_old_pass == NULL){
		printk("crypt error\n");
		kfree(input_old_pass);
		kfree(input_new_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	if(current->cred->euid.val != 0 || (strcmp(ref_monitor.pass, enc_old_pass) != 0)){
		printk("RUNNING WITHOUT EUID SET TO ROOT OR WRONG PASS\n");
		kfree(enc_old_pass);
		kfree(input_old_pass);
		kfree(input_new_pass);
		spin_unlock(&ref_monitor.lock);
	 	return -1;
	}
		
	get_random_bytes(salt, SALT_LENGTH);
	memcpy(ref_monitor.salt, salt, SALT_LENGTH);
	enc_new_pass = encrypt_password(input_new_pass, ref_monitor.salt);
	if (enc_new_pass == NULL) {
		printk("Error while password ciphering\n");
		kfree(enc_old_pass);
		kfree(input_old_pass);
		kfree(input_new_pass);
		spin_unlock(&ref_monitor.lock);
		return -1;
	}

	memcpy(ref_monitor.pass, enc_new_pass, strlen(enc_new_pass));

	kfree(enc_old_pass);
	kfree(enc_new_pass);
	kfree(input_old_pass);
	kfree(input_new_pass);
	spin_unlock(&ref_monitor.lock);
	printk("%s: Password CHANGED correctly\n", MODNAME);

	return 0;
	
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_ref_mon_on = (unsigned long) __x64_sys_ref_mon_on;
long sys_ref_mon_off = (unsigned long) __x64_sys_ref_mon_off;
long sys_ref_mon_rec_on = (unsigned long) __x64_sys_ref_mon_rec_on;
long sys_ref_mon_rec_off = (unsigned long) __x64_sys_ref_mon_rec_off;
long sys_ref_mon_add_path = (unsigned long) __x64_sys_ref_mon_add_path;
long sys_ref_mon_rm_path = (unsigned long) __x64_sys_ref_mon_rm_path;   
long sys_ref_mon_change_pass = (unsigned long) __x64_sys_ref_mon_change_pass;     
#else
#endif

int init_module(void) {

	int ret;
	int i;
	unsigned char salt[SALT_LENGTH];
	char *def_pass;

	printk("%s: initializing\n",MODNAME);

	get_random_bytes(salt, SALT_LENGTH);
	memcpy(ref_monitor.salt, salt, SALT_LENGTH);

	def_pass = encrypt_password(default_pass, ref_monitor.salt);
	if(def_pass == NULL){
		printk("crypt error\n");
		return -1;
	}

	ref_monitor.status = ON;
	ref_monitor.path[0] = NULL;
	ref_monitor.list_size = 0;
	memcpy(ref_monitor.pass, def_pass, strlen(def_pass));
	spin_lock_init(&(ref_monitor.lock));

	for(int j = 0; j < 3; j++){
		if((ref_monitor.path[j] = kmalloc(1024, GFP_KERNEL)) == NULL){
			printk("kmalloc error\n");
			return -1;
		}
	}

	strcat(ref_monitor.path[0], the_path);
	strcat(ref_monitor.path[0], "/user/test/black_test");
	strcat(ref_monitor.path[1], the_path);
	strcat(ref_monitor.path[1], "/user/test/files/pippo.txt");
	strcat(ref_monitor.path[2], the_path);
	strcat(ref_monitor.path[2], "/user/test/fakedir");
	ref_monitor.list_size = 3;

	AUDIT{
	    printk("%s: Reference-monitor received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
	    printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
	}

	new_sys_call_array[0] = (unsigned long) sys_ref_mon_on;
	new_sys_call_array[1] = (unsigned long) sys_ref_mon_off;
	new_sys_call_array[2] = (unsigned long) sys_ref_mon_rec_on;
	new_sys_call_array[3] = (unsigned long) sys_ref_mon_rec_off;
	new_sys_call_array[4] = (unsigned long) sys_ref_mon_add_path;
	new_sys_call_array[5] = (unsigned long) sys_ref_mon_rm_path;
	new_sys_call_array[6] = (unsigned long) sys_ref_mon_change_pass;

	ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);

	if (ret != HACKED_ENTRIES){
	        printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
	        return -1;      
	}

	unprotect_memory();

	for(i=0;i<HACKED_ENTRIES;i++){
	    ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
	}

	protect_memory();

	entry0 = restore[0];
	entry1 = restore[1];
	entry2 = restore[2];
	entry3 = restore[3];
	entry4 = restore[4];
	entry5 = restore[5];
	entry6 = restore[6];

	printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

	ret = register_kprobe(&kp_do_filp_open);
	if (ret < 0) {
	        printk("%s: kprobe do_filp_open registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = register_kprobe(&kp_do_mkdirat);
	if (ret < 0) {
	        printk("%s: kprobe do_mkdirat registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = register_kprobe(&kp_do_rmdir);
	if (ret < 0) {
	        printk("%s: kprobe do_rmdir registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = register_kprobe(&kp_do_unlinkat);
	if (ret < 0) {
	        printk("%s: kprobe do_unlinkat registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = register_kprobe(&kp_do_renameat2);
	if (ret < 0) {
	        printk("%s: kprobe do_renameat2 registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = register_kprobe(&kp_do_linkat);
	if (ret < 0) {
	        printk("%s: kprobe do_linkat registering failed, returned %d\n",MODNAME,ret);
	        return ret;
	}

	ret = 0;

	return ret;
}

void cleanup_module(void) {

	int i;        
	printk("%s: shutting down\n",MODNAME);

	unprotect_memory();
	for(i=0;i<HACKED_ENTRIES;i++){
	        ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
	}
	protect_memory();
	printk("%s: sys-call table restored to its original content\n",MODNAME);
	    
	//unregistering kprobes
	unregister_kprobe(&kp_do_filp_open);
	unregister_kprobe(&kp_do_mkdirat);
	unregister_kprobe(&kp_do_rmdir);
	unregister_kprobe(&kp_do_unlinkat);
	unregister_kprobe(&kp_do_renameat2);
	unregister_kprobe(&kp_do_linkat);
	   
	printk("%s: kprobes unregistered\n", MODNAME);
	printk("%s: Module correctly removed\n", MODNAME);
            
}

