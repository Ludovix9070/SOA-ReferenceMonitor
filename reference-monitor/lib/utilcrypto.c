#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <asm/segment.h>
 
#define PASSWORD_MAX_LENGTH 32
#define SHA256_DIGEST_SIZE 32
#define SALT_LENGTH 32
#define HASH_SIZE 32

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ludovico De Santis");
MODULE_DESCRIPTION("Encryption Module");


#define LIBNAME "UTILCRYPTO"


/*
* This function takes in input the password and a salt 
* to cipher the password, returning the encrypted password.
*/ 
char *encrypt_password(char *password, unsigned char *salt){
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned char digest[SHA256_DIGEST_SIZE];
    char encrypted_password[SALT_LENGTH+SHA256_DIGEST_SIZE];
    char *cipher;
    int ret;
    int i;

    cipher = kmalloc((SHA256_DIGEST_SIZE*2) +1, GFP_KERNEL);
    if (!cipher)
        return NULL;

    memcpy((unsigned char*)encrypted_password, salt, SALT_LENGTH);
    memcpy(encrypted_password + SALT_LENGTH, password, strlen(password));
    
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto out_free_mem;
    }
    
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }
    desc->tfm = tfm;
    
    ret = crypto_shash_digest(desc, encrypted_password, SALT_LENGTH + strlen(password), digest);
    if (ret) {
        pr_err("Errore durante la computazione dell'hash\n");
        goto out_free_desc;
    }
    
    kfree(desc);
    crypto_free_shash(tfm);
    
    pr_info("Password crittografata: ");
    for (i = 0; i < SHA256_DIGEST_SIZE; i++){
        pr_cont("%02x", digest[i]);
        sprintf(cipher + (i*2), "%02x", digest[i]);
    }

    pr_cont("\n");
    sprintf(cipher + (i*2), "%c", '\0');
    
    return cipher;
 
out_free_desc:
    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
out_free_mem:
    return NULL;
}


/*
* This function encrypts content to write on log-file.
*/ 
char *calculate_sha256(const char *data, unsigned int data_len, unsigned char *hash)
{
    struct crypto_shash *sha256;
    struct shash_desc *desc;
    int ret = -ENOMEM;
    char *encrypted_content;
    char *hash_ret;
    int i;

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256)) {
        pr_err("Failed to allocate SHA256\n");
        return NULL;
    }

    encrypted_content = kmalloc(data_len, GFP_KERNEL);
    if (!encrypted_content)
        return NULL;

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256), GFP_KERNEL);
    if (!desc) {
        pr_err("Failed to allocate shash descriptor\n");
        crypto_free_shash(sha256);
        return NULL;
    }

    hash_ret = kmalloc((HASH_SIZE*2) +1, GFP_KERNEL);
    if (!hash_ret)
        return NULL;

    desc->tfm = sha256;

    ret = crypto_shash_digest(desc, encrypted_content, data_len, hash);
    if (ret < 0) {
        pr_err("Failed to compute SHA256\n");
        kfree(desc);
        crypto_free_shash(sha256);
        return NULL;
    }

    for (i = 0; i < HASH_SIZE; i++){
        pr_cont("%02x", hash[i]);
        sprintf(hash_ret + (i*2), "%02x", hash[i]);
    }

    pr_cont("\n");
    sprintf(hash_ret + (i*2), "%c", '\0');

    kfree(desc);
    crypto_free_shash(sha256);

    return hash_ret;
}
 

