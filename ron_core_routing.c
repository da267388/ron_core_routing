#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_NAME "ron_core_routing"
#define BUFFER_SIZE 1024

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Danny");
MODULE_DESCRIPTION("Virtual File System in /proc ron");


static char proc_data[BUFFER_SIZE];
static ssize_t data_size = 0;

#define CORE_COUNT 64

static int routing[CORE_COUNT] = {0,  1,  2,  3,  32, 33, 34, 35, 4,  5,  6,  7,  36,
                          37, 38, 39, 8,  9,  10, 11, 40, 41, 42, 43, 12, 13,
                          14, 15, 44, 45, 46, 47, 24, 25, 26, 27, 56, 57, 58,
                          59, 28, 29, 30, 31, 60, 61, 62, 63, 16, 17, 18, 19,
                          48, 49, 50, 51, 20, 21, 22, 23, 52, 53, 54, 55};

// Function to convert the routing array into a string
static void routing_to_string(void) {
    int i;
    ssize_t offset = 0;

    for (i = 0; i < ARRAY_SIZE(routing); i++) {
        offset += scnprintf(proc_data + offset, BUFFER_SIZE - offset, "%d%s",
                            routing[i], (i < ARRAY_SIZE(routing) - 1) ? ", " : "\n");
        if (offset >= BUFFER_SIZE - 1) // Prevent buffer overflow
            break;
    }
    data_size = offset; // Update data size
}

// Print the routing array to the kernel log using printk
static void print_routing_array(void)
{
    int i;
    printk(KERN_INFO "Routing Array: ");
    for (i = 0; i < CORE_COUNT; i++) {
        printk(KERN_CONT "%d%s", routing[i], (i == CORE_COUNT - 1) ? "\n" : ", ");
    }
}

// Update the routing array from a user-supplied string
static int string_to_routing(const char *buffer, size_t len)
{
    int temp_routing[CORE_COUNT];
    int i = 0, count = 0;
    char *str, *token, *input;

    // Make a copy of the buffer to tokenize
    input = kmalloc(len + 1, GFP_KERNEL);
    if (!input) {
        pr_err("Failed to allocate memory in string_to_routing\n");
        return -ENOMEM;
    }
    strncpy(input, buffer, len);
    input[len] = '\0';

    // Parse the input string
    str = input;
    while ((token = strsep(&str, ", ")) != NULL) {
        if (kstrtoint(token, 10, &temp_routing[i]) == 0) {
            i++;
            if (i >= CORE_COUNT)
                break;
        } else {
            kfree(input);
            return -EINVAL; // Invalid input
        }
    }
    count = i;

    // Validate the number of values
    if (count != CORE_COUNT) {
        kfree(input);
        return -EINVAL;
    }

    // Copy the valid routing array
    memcpy(routing, temp_routing, sizeof(routing));
    kfree(input);
    
    print_routing_array();
    return 0;
}


static ssize_t proc_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
    if (*offset > 0 || len < data_size) // EOF or insufficient buffer
        return 0;
        
    // Ensure routing array is converted to a string
    routing_to_string();

    if (copy_to_user(buffer, proc_data, data_size))
        return -EFAULT;

    *offset = data_size;
    return data_size;
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset)
{
    if (len > BUFFER_SIZE - 1) // Check if input exceeds buffer size
        return -EINVAL;

    if (copy_from_user(proc_data, buffer, len))
        return -EFAULT;

    proc_data[len] = '\0'; // Null-terminate the string
    
    // Update routing array from the input string
    if (string_to_routing(proc_data, len) < 0)
        return -EINVAL;
    
    data_size = len;
    return len;
}

static const struct proc_ops vfs_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};


static int __init proc_init(void)
{
    struct proc_dir_entry *entry;
    

    entry = proc_create(PROC_NAME, 0666, NULL, &vfs_ops);

    if (!entry) {
        pr_err("myvfs: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    print_routing_array();

    return 0;
}

static void __exit proc_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
}

module_init(proc_init);
module_exit(proc_exit);
