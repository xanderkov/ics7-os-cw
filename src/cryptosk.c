/*
 * cryptosk.c
 */
#include <crypto/internal/skcipher.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/scatterlist.h>

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <linux/stddef.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <crypto/internal/hash.h>
#include <linux/module.h>
 

#include "my_ascii.h"
#include "hash.h"

 
#define SYMMETRIC_KEY_LENGTH 32
#define CIPHER_BLOCK_SIZE 16
 
struct tcrypt_result {
    struct completion completion;
    int err;
};
 
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
    char *scratchpad;
    char *ciphertext;
    char *ivdata;
};
 
static struct skcipher_def sk;

typedef struct
{
    struct work_struct work;
    int code;
} my_work_struct_t;

static struct workqueue_struct *my_wq;

static my_work_struct_t *work1;

int keyboard_irq = 1;
char *password = "password123";

#define SHA256_LENGTH 32
 
static void show_hash_result(char *plaintext, char *hash_sha256)
{
    int i;
    char str[SHA256_LENGTH * 2 + 1];
 
    pr_info("sha256 test for string: \"%s\"\n", plaintext);
    for (i = 0; i < SHA256_LENGTH; i++)
        sprintf(&str[i * 2], "%02x", (unsigned char)hash_sha256[i]);
    str[i * 2] = 0;
    pr_info("%s\n", str);
}

static int cryptosha256_init(char *plaintext) 
{
    char hash_sha256[SHA256_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;
 
    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256))
        return -1;
 
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256),
                    GFP_KERNEL);
    if (!shash)
        return -ENOMEM;
 
    shash->tfm = sha256;
 
    if (crypto_shash_init(shash))
        return -1;
 
    if (crypto_shash_update(shash, plaintext, strlen(plaintext)))
        return -1;
 
    if (crypto_shash_final(shash, hash_sha256))
        return -1;
 
    kfree(shash);
    crypto_free_shash(sha256);
 
    show_hash_result(plaintext, hash_sha256);
 
    return 0;
}
 
static void test_skcipher_finish(struct skcipher_def *sk)
{
    if (sk->tfm)
        crypto_free_skcipher(sk->tfm);
    if (sk->req)
        skcipher_request_free(sk->req);
    if (sk->ivdata)
        kfree(sk->ivdata);
    if (sk->scratchpad)
        kfree(sk->scratchpad);
    if (sk->ciphertext)
        kfree(sk->ciphertext);
}
 
static int test_skcipher_result(struct skcipher_def *sk, int rc)
{
    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS || -EBUSY:
        rc = wait_for_completion_interruptible(&sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
        pr_info("skcipher encrypt returned with %d result %d\n", rc,
                sk->result.err);
        break;
    default:
        pr_info("skcipher encrypt returned with %d result %d\n", rc,
                sk->result.err);
        break;
    }
 
    init_completion(&sk->result.completion);
 
    return rc;
}
 
static void test_skcipher_callback(void *req, int error)
{
    struct crypto_async_request *res = req;
    struct tcrypt_result *result = res->data;
 
    if (error == -EINPROGRESS) {
        pr_info("Error EINPROGRESS\n");
        return;

    }
        
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
 
    /* Расшифровка данных. */

    memset((void*)sk.scratchpad, '-', CIPHER_BLOCK_SIZE);
    int ret = crypto_skcipher_decrypt(sk.req);
    ret = test_skcipher_result(&sk, ret);
    if (ret) {
        pr_info("Error test_skcipher_result\n");
        return;

    }
 
    sg_copy_from_buffer(&sk.sg, 1, sk.scratchpad, CIPHER_BLOCK_SIZE);
    sk.scratchpad[CIPHER_BLOCK_SIZE-1] = 0;
 
    pr_info("Decryption request successful\n");
    pr_info("Decrypted: %s\n", sk.scratchpad);

}
 
static int test_skcipher_encrypt(char *plaintext, char *password,
                                 struct skcipher_def *sk)
{
    int ret = -EFAULT;
    unsigned char key[SYMMETRIC_KEY_LENGTH];
 
    if (!sk->tfm) {
        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
        if (IS_ERR(sk->tfm)) {
            pr_info("could not allocate skcipher handle\n");
            return PTR_ERR(sk->tfm);
        }
    }
 
    if (!sk->req) {
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
        if (!sk->req) {
            pr_info("could not allocate skcipher request\n");
            ret = -ENOMEM;
            return ret;
        }
    }
 
    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  test_skcipher_callback, &sk->result);
 
    /* Очистка ключа. */
    memset((void *)key, '\0', SYMMETRIC_KEY_LENGTH);
 
    sprintf((char *)key, "%s", password);
 
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        return ret;
    }
    pr_info("Symmetric key: %s\n", key);
    pr_info("Plaintext: %s\n", plaintext);
 
    if (!sk->ivdata) {
        sk->ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->ivdata) {
            pr_info("could not allocate ivdata\n");
            return ret;
        }
        get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
    }
 
    if (!sk->scratchpad) {
        /* Текст для шифрования. */
        sk->scratchpad = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->scratchpad) {
            pr_info("could not allocate scratchpad\n");
            return ret;
        }
    }
    sprintf((char *)sk->scratchpad, "%s", plaintext);
 
    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE);
    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE,
                               sk->ivdata);
    init_completion(&sk->result.completion);
 
    /* Шифрование данных. */
    ret = crypto_skcipher_encrypt(sk->req);
    ret = test_skcipher_result(sk, ret);
    if (ret)
        return ret;
    
    pr_info("Encrypted texted: %s\n", (char *)sk->scratchpad);
    pr_info("Encryption request successful\n");
 

    return ret;
}
 
void work1_func(struct work_struct *work)
{
    my_work_struct_t *my_work = (my_work_struct_t *)work;
    int code = my_work->code;

    printk(KERN_INFO "MyWorkQueue: work1 begin");

    if (code < 84)
        printk(KERN_INFO "MyWorkQueue: the key is %s", ascii[code]);

    printk(KERN_INFO "MyWorkQueue: work1 end");
}

irqreturn_t my_irq_handler(int irq, void *dev)
{
    int code;
    printk(KERN_INFO "MyWorkQueue: my_irq_handler");

    if (irq == keyboard_irq)
    {
        printk(KERN_INFO "MyWorkQueue: called by keyboard_irq");

        code = inb(0x60);
        work1->code = code;

        unsigned char mesage[SYMMETRIC_KEY_LENGTH];

        sprintf((char *)mesage, "%d", code);
        
        test_skcipher_encrypt((char *)mesage, password, &sk);


        queue_work(my_wq, (struct work_struct *)work1);

        return IRQ_HANDLED;
    }

    printk(KERN_INFO "MyWorkQueue: called not by keyboard_irq");

    return IRQ_NONE;
}

static int __init my_workqueue_init(void)
{
    int ret;
    
    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;

    ret = request_irq(keyboard_irq, my_irq_handler, IRQF_SHARED,
                      "test_my_irq_handler", (void *) my_irq_handler);

    printk(KERN_INFO "MyWorkQueue: init");
    if (ret)
    {
        printk(KERN_ERR "MyWorkQueue: request_irq error");
        return ret;
    }
    else
    {
        my_wq = alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, "my_wq");

        if (my_wq == NULL)
        {
            printk(KERN_ERR "MyWorkQueue: create queue error");
            ret = GFP_NOIO;
            return ret;
        }

        work1 = kmalloc(sizeof(my_work_struct_t), GFP_KERNEL);
        if (work1 == NULL)
        {
            printk(KERN_ERR "MyWorkQueue: work1 alloc error");
            destroy_workqueue(my_wq);
            ret = GFP_NOIO;
            return ret;
        }

        INIT_WORK((struct work_struct *)work1, work1_func);
        printk(KERN_ERR "MyWorkQueue: loaded");
    }
    int start = ktime_get();
    printk(KERN_INFO "MyWorkQueue: my_irq_handler");

    printk(KERN_INFO "MyWorkQueue: called by keyboard_irq");

    int code = 81;
    unsigned char mesage[SYMMETRIC_KEY_LENGTH];

    
    
    for (int i = 0; i < 100; i++)
    {
        sprintf((char *)mesage, "%d", code);
        pr_info("Plaintext: %s\n", (char *)mesage);
        // test_skcipher_encrypt((char *)mesage, password, &sk);
        // cryptosha256_init((char *)mesage);
    }

    int end = ktime_get();
    printk(KERN_INFO "Measured time: %d", end - start);

    return ret;
}

static void __exit my_workqueue_exit(void)
{
    printk(KERN_INFO "MyWorkQueue: exit");

    synchronize_irq(keyboard_irq); // ожидание завершения обработчика
    free_irq(keyboard_irq, my_irq_handler); // освобождение линни от обработчика

    flush_workqueue(my_wq);
    destroy_workqueue(my_wq);
    kfree(work1);

    
    printk(KERN_INFO "MyWorkQueue: unloaded");

    test_skcipher_finish(&sk);

    printk(KERN_INFO "Crypto: unloaded");
}
 
module_init(my_workqueue_init);
module_exit(my_workqueue_exit);
 
MODULE_DESCRIPTION("Symmetric key encryption example");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kovel A.");