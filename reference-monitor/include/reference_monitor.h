#define MODNAME "Reference monitor"
#define MAXSIZE 256
#define SALT_LENGTH 32
#define AUDIT if(1)
#define BUFFER_SIZE 4096
#define HASH_SIZE 32

enum {ON, OFF, RECON, RECOFF};

typedef struct reference_monitor {
	char 	      pass[65];
	unsigned char salt[32];
	int           status;
	char         *path[MAXSIZE];
	int           list_size;
	spinlock_t    lock;
	struct file   *file;
} t_monitor;

/*
* Informations to be written on the log-file in deferred work.
*/
typedef struct _packed_work{
        pid_t tgid;
        pid_t pid;
        uid_t uid;
        uid_t euid;
        char command_path[128];
        char command[64];
        struct work_struct the_work;
} packed_work;

struct open_flags {
	void* buffer;
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};