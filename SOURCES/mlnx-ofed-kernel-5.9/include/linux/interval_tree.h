#ifndef _COMPAT_LINUX_INTERVAL_TREE_H
#define _COMPAT_LINUX_INTERVAL_TREE_H

/* Include the autogenerated header file */
#include "../../compat/config.h"

#if (defined(HAVE_INTERVAL_TREE_EXPORTED) && !defined(CONFIG_INTERVAL_TREE)) || !defined(HAVE_INTERVAL_TREE_EXPORTED)
#define interval_tree_insert LINUX_BACKPORT(interval_tree_insert)
#define interval_tree_remove LINUX_BACKPORT(interval_tree_remove)
#define interval_tree_iter_first LINUX_BACKPORT(interval_tree_iter_first)
#define interval_tree_iter_next LINUX_BACKPORT(interval_tree_iter_next)
#endif

#include_next <linux/interval_tree.h>

#endif /* _COMPAT_LINUX_INTERVAL_TREE_H */