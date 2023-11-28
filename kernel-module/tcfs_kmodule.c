/*
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

static char *key = NULL;
static size_t key_size = 0;

SYSCALL_DEFINE2(putkey, char __user *, user_key, size_t, size)
{
char *new_key = kmalloc(size, GFP_KERNEL);
if (!new_key)
return -ENOMEM;

if (copy_from_user(new_key, user_key, size)) {
kfree(new_key);
return -EFAULT;
}

kfree(key);
key = new_key;
key_size = size;

return 0;
}

SYSCALL_DEFINE2(getkey, char __user *, user_key, size_t, size)
{
if (size < key_size)
return -EINVAL;

if (copy_to_user(user_key, key, key_size))
return -EFAULT;

return key_size;
}
*/