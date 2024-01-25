#ifndef NNT_DEFS_H
#define NNT_DEFS_H


#include <linux/kernel.h>
#include <linux/fs.h>


/* Passing MFT flag argument */
extern int is_mft_package;
extern struct driver_info nnt_driver_info;

#define NNT_DRIVER_NAME             "nnt_driver"
#define NNT_CLASS_NAME              "nnt_class"
#define NNT_DEVICE_PREFIX           "mt"
#define NNT_DRIVER                  "NNT Driver::"

#define CHECK_PCI_READ_ERROR(error, address) \
        if (error) { \
                nnt_error ("Failed to read from address: %x\n", address); \
                goto ReturnOnFinished; \
        }

#define CHECK_PCI_WRITE_ERROR(error, address, data) \
        if (error) { \
                nnt_error ("Failed to write to address: %x, data: %x\n", address, data); \
                goto ReturnOnFinished; \
        }

#define CHECK_ERROR(error) \
    if (error) { \
            goto ReturnOnFinished; \
    }

#define nnt_error(format, arg...) \
    pr_err("%s function name:%s, line:%d | " format, NNT_DRIVER, __func__, __LINE__, ## arg)

#define nnt_debug(format, arg...) \
    pr_debug("%s function name:%s, line: %d | " format, NNT_DRIVER, __func__, __LINE__, ## arg)


struct driver_info {
    dev_t device_number;
    int contiguous_device_numbers;
    struct class* class_driver;
};


#endif
