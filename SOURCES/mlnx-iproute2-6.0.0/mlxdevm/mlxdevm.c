/*
 * mlxdevm.c	mlxdevm tool
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Neta Ostrovsky <netao@nvidia.com>
 * 		Parav Pandit <parav@nvidia.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/mlxdevm_netlink.h>
#include <libmnl/libmnl.h>
#include <netinet/ether.h>
#include <rt_names.h>

#include "version.h"
#include "list.h"
#include "mnl_utils.h"
#include "json_print.h"
#include "utils.h"
#include "namespace.h"

#define PARAM_CMODE_RUNTIME_STR "runtime"
#define PARAM_CMODE_DRIVERINIT_STR "driverinit"

#define MLXDEVM_ARGS_REQUIRED_MAX_ERR_LEN 80

static int g_new_line_count;
static int g_indent_level;
static bool g_indent_newline;

#define INDENT_STR_STEP 2
#define INDENT_STR_MAXLEN 32
static char g_indent_str[INDENT_STR_MAXLEN + 1] = "";

static void __attribute__((format(printf, 1, 2)))
pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void __attribute__((format(printf, 1, 2)))
pr_out(const char *fmt, ...)
{
	va_list ap;

	if (g_indent_newline) {
		printf("%s", g_indent_str);
		g_indent_newline = false;
	}
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	g_new_line_count = 0;
}

static void __pr_out_indent_inc(void)
{
	if (g_indent_level + INDENT_STR_STEP > INDENT_STR_MAXLEN)
		return;
	g_indent_level += INDENT_STR_STEP;
	memset(g_indent_str, ' ', sizeof(g_indent_str));
	g_indent_str[g_indent_level] = '\0';
}

static void __pr_out_indent_dec(void)
{
	if (g_indent_level - INDENT_STR_STEP < 0)
		return;
	g_indent_level -= INDENT_STR_STEP;
	g_indent_str[g_indent_level] = '\0';
}

static void __pr_out_newline(void)
{
	if (g_new_line_count < 1) {
		pr_out("\n");
		g_indent_newline = true;
	}
	g_new_line_count++;
}

struct ifname_map {
	struct list_head list;
	char *bus_name;
	char *dev_name;
	uint32_t port_index;
	char *ifname;
};

static void ifname_map_free(struct ifname_map *ifname_map)
{
	free(ifname_map->ifname);
	free(ifname_map->dev_name);
	free(ifname_map->bus_name);
	free(ifname_map);
}

static struct ifname_map *ifname_map_alloc(const char *bus_name,
					   const char *dev_name,
					   uint32_t port_index,
					   const char *ifname)
{
	struct ifname_map *ifname_map;

	ifname_map = calloc(1, sizeof(*ifname_map));
	if (!ifname_map)
		return NULL;
	ifname_map->bus_name = strdup(bus_name);
	ifname_map->dev_name = strdup(dev_name);
	ifname_map->port_index = port_index;
	ifname_map->ifname = strdup(ifname);
	if (!ifname_map->bus_name || !ifname_map->dev_name ||
	    !ifname_map->ifname) {
		ifname_map_free(ifname_map);
		return NULL;
	}
	return ifname_map;
}

#define MLXDEVM_OPT_HANDLE			BIT(0)
#define MLXDEVM_OPT_HANDLEP			BIT(1)
#define MLXDEVM_OPT_PORT_FLAVOUR		BIT(2)
#define MLXDEVM_OPT_PORT_PFNUMBER		BIT(3)
#define MLXDEVM_OPT_PORT_SFNUMBER		BIT(4)
#define MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR	BIT(5)
#define MLXDEVM_OPT_PORT_FUNCTION_STATE		BIT(6)
#define MLXDEVM_OPT_PARAM_NAME			BIT(7)
#define MLXDEVM_OPT_PARAM_VALUE			BIT(8)
#define MLXDEVM_OPT_PARAM_CMODE			BIT(9)
#define MLXDEVM_OPT_PORT_FN_CAP_ROCE		BIT(10)
#define MLXDEVM_OPT_PORT_CONTROLLER		BIT(11)
#define MLXDEVM_OPT_PORT_FN_CAP_UC_LIST		BIT(12)
#define MLXDEVM_OPT_PORT_FN_RATE_TYPE		BIT(13)
#define MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME	BIT(14)
#define MLXDEVM_OPT_PORT_FN_RATE_TX_SHARE	BIT(15)
#define MLXDEVM_OPT_PORT_FN_RATE_TX_MAX		BIT(16)
#define MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME BIT(17)
#define MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE   BIT(18)

struct mlxdevm_opts {
	uint64_t present; /* flags of present items */
	char *bus_name;
	char *dev_name;
	uint32_t port_index;
	uint32_t port_controller;
	uint32_t port_sfnumber;
	uint16_t port_flavour;
	uint16_t port_pfnumber;
	char port_function_hw_addr[MAX_ADDR_LEN];
	uint32_t port_function_hw_addr_len;
	uint8_t port_fn_state;
	const char *param_name;
	const char *param_value;
	enum mlxdevm_param_cmode cmode;
	uint8_t port_fn_cap_roce;
	uint32_t port_fn_cap_max_uc_list;
	uint16_t port_function_rate_type;
	char *rate_node_name;
	uint64_t port_function_rate_tx_share;
	uint64_t port_function_rate_tx_max;
	const char *rate_parent_node;
	uint8_t port_fn_trust;
};

struct mlxdevm {
	struct mnlu_gen_socket nlg;
	struct list_head ifname_map_list;
	int argc;
	char **argv;
	bool no_nice_names;
	struct mlxdevm_opts opts;
	bool json_output;
	bool pretty_output;
	bool verbose;
	struct {
		bool present;
		char *bus_name;
		char *dev_name;
		uint32_t port_index;
	} arr_last;
};

static void pr_out_handle_end(struct mlxdevm *mlxdevm);

static int mlxdevm_argc(struct mlxdevm *mlxdevm)
{
	return mlxdevm->argc;
}

static char *mlxdevm_argv(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argc(mlxdevm) == 0)
		return NULL;
	return *mlxdevm->argv;
}

static void mlxdevm_arg_inc(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argc(mlxdevm) == 0)
		return;
	mlxdevm->argc--;
	mlxdevm->argv++;
}

static char *mlxdevm_argv_next(struct mlxdevm *mlxdevm)
{
	char *ret;

	if (mlxdevm_argc(mlxdevm) == 0)
		return NULL;

	ret = *mlxdevm->argv;
	mlxdevm_arg_inc(mlxdevm);
	return ret;
}

static int strcmpx(const char *str1, const char *str2)
{
	if (strlen(str1) > strlen(str2))
		return -1;
	return strncmp(str1, str2, strlen(str1));
}

static bool mlxdevm_argv_match(struct mlxdevm *mlxdevm, const char *pattern)
{
	if (mlxdevm_argc(mlxdevm) == 0)
		return false;
	return strcmpx(mlxdevm_argv(mlxdevm), pattern) == 0;
}

static bool mlxdevm_no_arg(struct mlxdevm *mlxdevm)
{
	return mlxdevm_argc(mlxdevm) == 0;
}

static void __pr_out_indent_newline(struct mlxdevm *mlxdevm)
{
	if (!g_indent_newline && !mlxdevm->json_output)
		pr_out(" ");
}

static void pr_out_section_start(struct mlxdevm *mlxdevm, const char *name)
{
	if (mlxdevm->json_output) {
		open_json_object(NULL);
		open_json_object(name);
	}
}

static void pr_out_section_end(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output) {
		if (mlxdevm->arr_last.present)
			close_json_array(PRINT_JSON, NULL);
		close_json_object();
		close_json_object();
	}
}

static void pr_out_array_start(struct mlxdevm *mlxdevm, const char *name)
{
	if (mlxdevm->json_output) {
		open_json_array(PRINT_JSON, name);
	} else {
		__pr_out_indent_inc();
		__pr_out_newline();
		pr_out("%s:", name);
		__pr_out_indent_inc();
		__pr_out_newline();
	}
}

static void pr_out_array_end(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output) {
		close_json_array(PRINT_JSON, NULL);
	} else {
		__pr_out_indent_dec();
		__pr_out_indent_dec();
	}
}

static void pr_out_object_start(struct mlxdevm *mlxdevm, const char *name)
{
	if (mlxdevm->json_output) {
		open_json_object(name);
	} else {
		__pr_out_indent_inc();
		__pr_out_newline();
		pr_out("%s:", name);
		__pr_out_indent_inc();
		__pr_out_newline();
	}
}

static void pr_out_object_end(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output) {
		close_json_object();
	} else {
		__pr_out_indent_dec();
		__pr_out_indent_dec();
	}
}

static void pr_out_entry_start(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output)
		open_json_object(NULL);
}

static void pr_out_entry_end(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output)
		close_json_object();
	else
		__pr_out_newline();
}

static void check_indent_newline(struct mlxdevm *mlxdevm)
{
	__pr_out_indent_newline(mlxdevm);

	if (g_indent_newline && !is_json_context()) {
		printf("%s", g_indent_str);
		g_indent_newline = false;
	}
	g_new_line_count = 0;
}

static const enum mnl_attr_data_type mlxdevm_policy[MLXDEVM_ATTR_MAX + 1] = {
	[MLXDEVM_ATTR_DEV_BUS_NAME] = MNL_TYPE_NUL_STRING,
	[MLXDEVM_ATTR_DEV_NAME] = MNL_TYPE_NUL_STRING,
	[MLXDEVM_ATTR_PORT_INDEX] = MNL_TYPE_U32,
	[MLXDEVM_ATTR_PORT_NETDEV_NAME] = MNL_TYPE_NUL_STRING,
	[MLXDEVM_ATTR_PORT_IBDEV_NAME] = MNL_TYPE_NUL_STRING,
	[MLXDEVM_ATTR_PARAM] = MNL_TYPE_NESTED,
	[MLXDEVM_ATTR_PARAM_NAME] = MNL_TYPE_STRING,
	[MLXDEVM_ATTR_PARAM_TYPE] = MNL_TYPE_U8,
	[MLXDEVM_ATTR_PARAM_VALUES_LIST] = MNL_TYPE_NESTED,
	[MLXDEVM_ATTR_PARAM_VALUE] = MNL_TYPE_NESTED,
	[MLXDEVM_ATTR_PARAM_VALUE_CMODE] = MNL_TYPE_U8,
};

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, MLXDEVM_ATTR_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, mlxdevm_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static const enum mnl_attr_data_type
mlxdevm_function_policy[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1] = {
	[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR] = MNL_TYPE_BINARY,
	[MLXDEVM_PORT_FN_ATTR_STATE] = MNL_TYPE_U8,
	[MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE] = MNL_TYPE_U8,
	[MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST] = MNL_TYPE_U32,
	[MLXDEVM_PORT_FN_ATTR_TRUST_STATE] = MNL_TYPE_U8,
};

static int function_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	/* Allow the tool to work on top of newer kernels that might contain
	 * more attributes.
	 */
	if (mnl_attr_type_valid(attr, MLXDEVM_PORT_FUNCTION_ATTR_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, mlxdevm_function_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int ifname_map_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct mlxdevm *mlxdevm = data;
	struct ifname_map *ifname_map;
	const char *bus_name;
	const char *dev_name;
	uint32_t port_ifindex;
	const char *port_ifname;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME] ||
	    !tb[MLXDEVM_ATTR_PORT_INDEX])
		return MNL_CB_ERROR;

	if (!tb[MLXDEVM_ATTR_PORT_NETDEV_NAME])
		return MNL_CB_OK;

	bus_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_BUS_NAME]);
	dev_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_NAME]);
	port_ifindex = mnl_attr_get_u32(tb[MLXDEVM_ATTR_PORT_INDEX]);
	port_ifname = mnl_attr_get_str(tb[MLXDEVM_ATTR_PORT_NETDEV_NAME]);
	ifname_map = ifname_map_alloc(bus_name, dev_name,
				      port_ifindex, port_ifname);
	if (!ifname_map)
		return MNL_CB_ERROR;
	list_add(&ifname_map->list, &mlxdevm->ifname_map_list);

	return MNL_CB_OK;
}

static void ifname_map_fini(struct mlxdevm *mlxdevm)
{
	struct ifname_map *ifname_map, *tmp;

	list_for_each_entry_safe(ifname_map, tmp,
				 &mlxdevm->ifname_map_list, list) {
		list_del(&ifname_map->list);
		ifname_map_free(ifname_map);
	}
}

static int ifname_map_init(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err;

	INIT_LIST_HEAD(&mlxdevm->ifname_map_list);

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_PORT_GET,
					  NLM_F_REQUEST | NLM_F_ACK |
					  NLM_F_DUMP);

	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, ifname_map_cb,
				     mlxdevm);
	if (err) {
		ifname_map_fini(mlxdevm);
		return err;
	}
	return 0;
}

static int ifname_map_lookup(struct mlxdevm *mlxdevm, const char *ifname,
			     char **p_bus_name, char **p_dev_name,
			     uint32_t *p_port_index)
{
	struct ifname_map *ifname_map;

	list_for_each_entry(ifname_map, &mlxdevm->ifname_map_list, list) {
		if (strcmp(ifname, ifname_map->ifname) == 0) {
			*p_bus_name = ifname_map->bus_name;
			*p_dev_name = ifname_map->dev_name;
			*p_port_index = ifname_map->port_index;
			return 0;
		}
	}
	return -ENOENT;
}

static int ifname_map_rev_lookup(struct mlxdevm *mlxdevm,
				 const char *bus_name, const char *dev_name,
				 uint32_t port_index, char **p_ifname)
{
	struct ifname_map *ifname_map;

	list_for_each_entry(ifname_map, &mlxdevm->ifname_map_list, list) {
		if (strcmp(bus_name, ifname_map->bus_name) == 0 &&
		    strcmp(dev_name, ifname_map->dev_name) == 0 &&
		    port_index == ifname_map->port_index) {
			*p_ifname = ifname_map->ifname;
			return 0;
		}
	}
	return -ENOENT;
}

static int strtouint64_t(const char *str, uint64_t *p_val)
{
	char *endptr;
	unsigned long long int val;

	val = strtoull(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > ULONG_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtouint32_t(const char *str, uint32_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > UINT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtouint16_t(const char *str, uint16_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > USHRT_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtouint8_t(const char *str, uint8_t *p_val)
{
	char *endptr;
	unsigned long int val;

	val = strtoul(str, &endptr, 10);
	if (endptr == str || *endptr != '\0')
		return -EINVAL;
	if (val > UCHAR_MAX)
		return -ERANGE;
	*p_val = val;
	return 0;
}

static int strtobool(const char *str, bool *p_val)
{
	bool val;

	if (!strcmp(str, "true") || !strcmp(str, "1") ||
	    !strcmp(str, "enable"))
		val = true;
	else if (!strcmp(str, "false") || !strcmp(str, "0") ||
		 !strcmp(str, "disable"))
		val = false;
	else
		return -EINVAL;
	*p_val = val;
	return 0;
}

static int __mlxdevm_argv_handle(char *str, char **p_bus_name,
				 char **p_dev_name)
{
	str_split_by_char(str, p_bus_name, p_dev_name, '/');
	return 0;
}

static int mlxdevm_argv_handle(struct mlxdevm *mlxdevm, char **p_bus_name,
			       char **p_dev_name)
{
	char *str = mlxdevm_argv_next(mlxdevm);

	if (!str) {
		pr_err("mlxdevm identification (\"bus_name/dev_name\") expected\n");
		return -EINVAL;
	}
	if (get_str_char_count(str, '/') != 1) {
		pr_err("Wrong mlxdevm identification string format.\n");
		pr_err("Expected \"bus_name/dev_name\".\n");
		return -EINVAL;
	}
	return __mlxdevm_argv_handle(str, p_bus_name, p_dev_name);
}

static int __mlxdevm_argv_handle_port(char *str, char **p_bus_name,
				      char **p_dev_name,
				      uint32_t *p_port_index)
{
	char *handlestr;
	char *portstr;
	int err;

	err = str_split_by_char(str, &handlestr, &portstr, '/');
	if (err) {
		pr_err("Port identification \"%s\" is invalid\n", str);
		return err;
	}
	err = strtouint32_t(portstr, p_port_index);
	if (err) {
		pr_err("Port index \"%s\" is not a number or not within range\n",
		       portstr);
		return err;
	}
	err = str_split_by_char(handlestr, p_bus_name, p_dev_name, '/');
	if (err) {
		pr_err("Port identification \"%s\" is invalid\n", str);
		return err;
	}
	return 0;
}

static int __mlxdevm_argv_handle_port_ifname(struct mlxdevm *mlxdevm,
					     char *str, char **p_bus_name,
					     char **p_dev_name,
					     uint32_t *p_port_index)
{
	int err;

	err = ifname_map_lookup(mlxdevm, str, p_bus_name, p_dev_name,
				p_port_index);
	if (err) {
		pr_err("Netdevice \"%s\" not found\n", str);
		return err;
	}
	return 0;
}

static int mlxdevm_argv_handle_port(struct mlxdevm *mlxdevm,
				    char **p_bus_name, char **p_dev_name,
				    uint32_t *p_port_index)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	unsigned int slash_count;

	if (!str) {
		pr_err("Port identification (\"bus_name/dev_name/port_index\" or \"netdev ifname\") expected.\n");
		return -EINVAL;
	}
	slash_count = get_str_char_count(str, '/');
	switch (slash_count) {
	case 0:
		return __mlxdevm_argv_handle_port_ifname(mlxdevm, str,
							 p_bus_name,
							 p_dev_name,
							 p_port_index);
	case 2:
		return __mlxdevm_argv_handle_port(str, p_bus_name,
						  p_dev_name, p_port_index);
	default:
		pr_err("Wrong port identification string format.\n");
		pr_err("Expected \"bus_name/dev_name/port_index\" or \"netdev_ifname\".\n");
		return -EINVAL;
	}
}

static int mlxdevm_argv_handle_both(struct mlxdevm *mlxdevm,
				    char **p_bus_name, char **p_dev_name,
				    uint32_t *p_port_index,
				    uint64_t *p_handle_bit)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	unsigned int slash_count;
	int err;

	if (!str) {
		pr_err("One of following identifications expected:\n"
		       "mlxdevm identification (\"bus_name/dev_name\")\n"
		       "Port identification (\"bus_name/dev_name/port_index\" or \"netdev ifname\")\n");
		return -EINVAL;
	}
	slash_count = get_str_char_count(str, '/');
	if (slash_count == 1) {
		err = __mlxdevm_argv_handle(str, p_bus_name, p_dev_name);
		if (err)
			return err;
		*p_handle_bit = MLXDEVM_OPT_HANDLE;
	} else if (slash_count == 2) {
		err = __mlxdevm_argv_handle_port(str, p_bus_name,
						 p_dev_name, p_port_index);
		if (err)
			return err;
		*p_handle_bit = MLXDEVM_OPT_HANDLEP;
	} else if (slash_count == 0) {
		err = __mlxdevm_argv_handle_port_ifname(mlxdevm, str,
							p_bus_name,
							p_dev_name,
							p_port_index);
		if (err)
			return err;
		*p_handle_bit = MLXDEVM_OPT_HANDLEP;
	} else {
		pr_err("Wrong port identification string format.\n");
		pr_err("Expected \"bus_name/dev_name\" or \"bus_name/dev_name/port_index\" or \"netdev_ifname\".\n");
		return -EINVAL;
	}
	return 0;
}

static int mlxdevm_argv_uint64_t(struct mlxdevm *mlxdevm, uint64_t *p_val)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint64_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int mlxdevm_argv_uint32_t(struct mlxdevm *mlxdevm, uint32_t *p_val)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint32_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int mlxdevm_argv_uint16_t(struct mlxdevm *mlxdevm, uint16_t *p_val)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	int err;

	if (!str) {
		pr_err("Unsigned number argument expected\n");
		return -EINVAL;
	}

	err = strtouint16_t(str, p_val);
	if (err) {
		pr_err("\"%s\" is not a number or not within range\n", str);
		return err;
	}
	return 0;
}

static int mlxdevm_argv_str(struct mlxdevm *mlxdevm, const char **p_str)
{
	const char *str = mlxdevm_argv_next(mlxdevm);

	if (!str) {
		pr_err("String parameter expected\n");
		return -EINVAL;
	}
	*p_str = str;
	return 0;
}

static int param_cmode_get(const char *cmodestr,
			   enum mlxdevm_param_cmode *cmode)
{
	if (strcmp(cmodestr, PARAM_CMODE_RUNTIME_STR) == 0) {
		*cmode = MLXDEVM_PARAM_CMODE_RUNTIME;
	} else if (strcmp(cmodestr, PARAM_CMODE_DRIVERINIT_STR) == 0) {
		*cmode = MLXDEVM_PARAM_CMODE_DRIVERINIT;
	} else {
		pr_err("Unknown configuration mode \"%s\"\n", cmodestr);
		return -EINVAL;
	}
	return 0;
}

static int hw_addr_parse(const char *addrstr, char *hw_addr, uint32_t *len)
{
	int alen;

	alen = ll_addr_a2n(hw_addr, MAX_ADDR_LEN, addrstr);
	if (alen < 0)
		return -EINVAL;
	*len = alen;
	return 0;
}

static struct str_num_map port_flavour_map[] = {
	{ .str = "physical", .num = MLXDEVM_PORT_FLAVOUR_PHYSICAL },
	{ .str = "cpu", .num = MLXDEVM_PORT_FLAVOUR_CPU },
	{ .str = "dsa", .num = MLXDEVM_PORT_FLAVOUR_DSA },
	{ .str = "pcipf", .num = MLXDEVM_PORT_FLAVOUR_PCI_PF },
	{ .str = "pcivf", .num = MLXDEVM_PORT_FLAVOUR_PCI_VF },
	{ .str = "pcisf", .num = MLXDEVM_PORT_FLAVOUR_PCI_SF },
	{ .str = "virtual", .num = MLXDEVM_PORT_FLAVOUR_VIRTUAL},
	{ .str = NULL, },
};

static struct str_num_map port_fn_state_map[] = {
	{ .str = "inactive", .num = MLXDEVM_PORT_FN_STATE_INACTIVE},
	{ .str = "active", .num = MLXDEVM_PORT_FN_STATE_ACTIVE },
	{ .str = NULL, }
};

static struct str_num_map port_fn_opstate_map[] = {
	{ .str = "attached", .num = MLXDEVM_PORT_FN_OPSTATE_ATTACHED},
	{ .str = "detached", .num = MLXDEVM_PORT_FN_OPSTATE_DETACHED},
	{ .str = NULL, }
};

static struct str_num_map port_fn_trust_map[] = {
	{ .str = "on", .num = MLXDEVM_PORT_FN_TRUSTED},
	{ .str = "off", .num =  MLXDEVM_PORT_FN_UNTRUSTED},
	{ .str = NULL, }
};

static int port_flavour_parse(const char *flavour, uint16_t *value)
{
	int num;

	num = str_map_lookup_str(port_flavour_map, flavour);
	if (num < 0) {
		invarg("unknown flavour", flavour);
		return num;
	}
	*value = num;
	return 0;
}

static int port_fn_trust_parse(const char *statestr, uint8_t *trust)
{
	int num;

	num = str_map_lookup_str(port_fn_trust_map, statestr);
	if (num < 0) {
		invarg("unknown state", statestr);
		return num;
	}
	*trust = num;
	return 0;
}

static int port_fn_state_parse(const char *statestr, uint8_t *state)
{
	int num;

	num = str_map_lookup_str(port_fn_state_map, statestr);
	if (num < 0) {
		invarg("unknown state", statestr);
		return num;
	}
	*state = num;
	return 0;
}

static struct str_num_map port_fn_cap_roce_map[] = {
	{ .str = "false", .num = MLXDEVM_PORT_FN_CAP_ROCE_DISABLE },
	{ .str = "true", .num = MLXDEVM_PORT_FN_CAP_ROCE_ENABLE},
	{ .str = NULL, }
};

static int port_fn_cap_roce_parse(const char *statestr, uint8_t *state)
{
	int num;

	num = str_map_lookup_str(port_fn_cap_roce_map, statestr);
	if (num < 0) {
		invarg ("unknown state", statestr);
		return num;
	}
	*state = num;
	return 0;
}

struct mlxdevm_args_metadata {
	uint64_t o_flag;
	char err_msg[MLXDEVM_ARGS_REQUIRED_MAX_ERR_LEN];
};

static const struct mlxdevm_args_metadata mlxdevm_args_required[] = {
	{MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR,	"Port function's hardware address is expected."},
	{MLXDEVM_OPT_PORT_FLAVOUR,		"Port flavour is expected."},
	{MLXDEVM_OPT_PORT_PFNUMBER,		"Port PCI PF number is expected."},
	{MLXDEVM_OPT_PARAM_NAME,		"Parameter name expected."},
	{MLXDEVM_OPT_PARAM_VALUE,		"Value to set expected."},
	{MLXDEVM_OPT_PARAM_CMODE,		"Configuration mode expected."},
	{MLXDEVM_OPT_PORT_FN_CAP_ROCE,		"Port function's roce capability state is expected."},
	{MLXDEVM_OPT_PORT_FN_CAP_UC_LIST,	"Port function's max uc list capability value is expected."},
	{MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE,	"Port function's trust state expected."},
};

static int mlxdevm_args_finding_required_validate(uint64_t o_required,
						   uint64_t o_found)
{
	uint64_t o_flag;
	int i;

	for (i = 0; i < ARRAY_SIZE(mlxdevm_args_required); i++) {
		o_flag = mlxdevm_args_required[i].o_flag;
		if ((o_required & o_flag) && !(o_found & o_flag)) {
			pr_err("%s\n", mlxdevm_args_required[i].err_msg);
			return -EINVAL;
		}
	}
	if (o_required & ~o_found) {
		pr_err("BUG: unknown argument required but not found\n");
		return -EINVAL;
	}
	return 0;
}

static int mlxdevm_argv_handle_rate(struct mlxdevm *mlxdevm, char **p_bus_name,
			       char **p_dev_name, uint32_t *p_port_index,
			       char **node_name, uint16_t *rate_type, uint64_t *p_handle_bit)
{
	char *str = mlxdevm_argv_next(mlxdevm);
	unsigned int slash_count;
	char *identifier;
	char *handlestr;
	int err = -EINVAL;

	slash_count = get_str_char_count(str, '/');
	if (slash_count != 2) {
		pr_err("Expected \"bus_name/dev_name/node\" or "
		       "\"bus_name/dev_name/port_index\" identification.\n");
		return err;
	}

	err = str_split_by_char(str, &handlestr, &identifier, '/');
	if (err) {
		pr_err("Identification \"%s\" is invalid\n", str);
		return err;
	}

	if (!*identifier) {
		pr_err("Identifier cannot be empty");
		return -EINVAL;
	}

	err = str_split_by_char(handlestr, p_bus_name, p_dev_name, '/');
	if (err) {
		pr_err("Port identification \"%s\" is invalid\n", str);
		return err;
	}

	if (strspn(identifier, "0123456789") == strlen(identifier)) {
		err = strtouint32_t(identifier, p_port_index);
		if (err) {
			pr_err("Port index \"%s\" is not a number"
			       " or not within range\n", identifier);
			return err;
		}
		*rate_type = MLXDEVM_RATE_EXT_TYPE_LEAF;
		*p_handle_bit = MLXDEVM_OPT_HANDLEP | MLXDEVM_OPT_PORT_FN_RATE_TYPE;
	} else {
		*node_name = identifier;
		*rate_type = MLXDEVM_RATE_EXT_TYPE_NODE;
		*p_handle_bit = MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME | MLXDEVM_OPT_PORT_FN_RATE_TYPE;
	}

	return 0;
}

static int mlxdevm_argv_parse(struct mlxdevm *mlxdevm, uint64_t o_required,
			 uint64_t o_optional)
{
	struct mlxdevm_opts *opts = &mlxdevm->opts;
	uint64_t o_all = o_required | o_optional;
	uint64_t o_found = 0;
	int err;

	if (o_required & MLXDEVM_OPT_HANDLEP &&
	    o_required & MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME) {
		uint64_t handle_bit;

		err = mlxdevm_argv_handle_rate(mlxdevm, &opts->bus_name,
					       &opts->dev_name,
					       &opts->port_index,
					       &opts->rate_node_name,
					       &opts->port_function_rate_type,
					       &handle_bit);
		if (err)
			return err;
		o_required &= ~(MLXDEVM_OPT_HANDLEP | MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME) | handle_bit;
		o_found |= handle_bit;
	} else if (o_required & MLXDEVM_OPT_HANDLE && o_required & MLXDEVM_OPT_HANDLEP) {
		uint64_t handle_bit;

		err = mlxdevm_argv_handle_both(mlxdevm, &opts->bus_name,
					       &opts->dev_name,
					       &opts->port_index,
					       &handle_bit);
		if (err)
			return err;
		o_required &= ~(MLXDEVM_OPT_HANDLE | MLXDEVM_OPT_HANDLEP) |
				handle_bit;
		o_found |= handle_bit;
	} else if (o_required & MLXDEVM_OPT_HANDLE) {
		err = mlxdevm_argv_handle(mlxdevm, &opts->bus_name,
					  &opts->dev_name);
		if (err)
			return err;
		o_found |= MLXDEVM_OPT_HANDLE;
	} else if (o_required & MLXDEVM_OPT_HANDLEP) {
		err = mlxdevm_argv_handle_port(mlxdevm, &opts->bus_name,
					       &opts->dev_name,
					       &opts->port_index);
		if (err)
			return err;
		o_found |= MLXDEVM_OPT_HANDLEP;
	}

	while (mlxdevm_argc(mlxdevm)) {
		if (mlxdevm_argv_match(mlxdevm, "hw_addr") &&
			   (o_all & MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR)) {
			const char *addrstr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &addrstr);
			if (err)
				return err;
			err = hw_addr_parse(addrstr,
					    opts->port_function_hw_addr,
					    &opts->port_function_hw_addr_len);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR;
		} else if (mlxdevm_argv_match(mlxdevm, "state") &&
			   (o_all & MLXDEVM_OPT_PORT_FUNCTION_STATE)) {
			const char *statestr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &statestr);
			if (err)
				return err;
			err = port_fn_state_parse(statestr,
						  &opts->port_fn_state);
			if (err)
				return err;

			o_found |= MLXDEVM_OPT_PORT_FUNCTION_STATE;
		} else if (mlxdevm_argv_match(mlxdevm, "trust") &&
			   (o_all & MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE)) {
			const char *statestr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &statestr);
			if (err)
				return err;
			err = port_fn_trust_parse(statestr, &opts->port_fn_trust);
			if (err)
				return err;

			o_found |= MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE;
		} else if (mlxdevm_argv_match(mlxdevm, "flavour") &&
		   (o_all & MLXDEVM_OPT_PORT_FLAVOUR)) {
			const char *flavourstr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &flavourstr);
			if (err)
				return err;
			err = port_flavour_parse(flavourstr,
						 &opts->port_flavour);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FLAVOUR;
		} else if (mlxdevm_argv_match(mlxdevm, "pfnum") &&
			  (o_all & MLXDEVM_OPT_PORT_PFNUMBER)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint16_t(mlxdevm,
						    &opts->port_pfnumber);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_PFNUMBER;
		} else if (mlxdevm_argv_match(mlxdevm, "sfnum") &&
			  (o_all & MLXDEVM_OPT_PORT_SFNUMBER)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint32_t(mlxdevm,
						    &opts->port_sfnumber);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_SFNUMBER;
		} else if (mlxdevm_argv_match(mlxdevm, "name") &&
			   (o_all & MLXDEVM_OPT_PARAM_NAME)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &opts->param_name);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PARAM_NAME;
		} else if (mlxdevm_argv_match(mlxdevm, "value") &&
			   (o_all & MLXDEVM_OPT_PARAM_VALUE)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &opts->param_value);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PARAM_VALUE;
		} else if (mlxdevm_argv_match(mlxdevm, "cmode") &&
			   (o_all & MLXDEVM_OPT_PARAM_CMODE)) {
			const char *cmodestr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &cmodestr);
			if (err)
				return err;
			err = param_cmode_get(cmodestr, &opts->cmode);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PARAM_CMODE;
		} else if (mlxdevm_argv_match(mlxdevm, "roce") &&
			   (o_all & MLXDEVM_OPT_PORT_FN_CAP_ROCE)) {
			const char *statestr;

			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &statestr);
			if (err)
				return err;
			err = port_fn_cap_roce_parse(statestr,
						  &opts->port_fn_cap_roce);
			if (err)
				return err;

			o_found |= MLXDEVM_OPT_PORT_FN_CAP_ROCE;
		} else if (mlxdevm_argv_match(mlxdevm, "controller") &&
			   (o_all & MLXDEVM_OPT_PORT_CONTROLLER)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint32_t(mlxdevm, &opts->port_controller);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_CONTROLLER;
		} else if (mlxdevm_argv_match(mlxdevm, "max_uc_macs") &&
			  (o_all & MLXDEVM_OPT_PORT_FN_CAP_UC_LIST)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint32_t(mlxdevm,
						    &opts->port_fn_cap_max_uc_list);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FN_CAP_UC_LIST;
		} else if (mlxdevm_argv_match(mlxdevm, "tx_share") &&
			  (o_all & MLXDEVM_OPT_PORT_FN_RATE_TX_SHARE)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint64_t(mlxdevm,
						     &opts->port_function_rate_tx_share);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FN_RATE_TX_SHARE;
		} else if (mlxdevm_argv_match(mlxdevm, "tx_max") &&
			  (o_all & MLXDEVM_OPT_PORT_FN_RATE_TX_MAX)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_uint64_t(mlxdevm,
						     &opts->port_function_rate_tx_max);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FN_RATE_TX_MAX;
		} else if (mlxdevm_argv_match(mlxdevm, "parent") &&
			  (o_all & MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME)) {
			mlxdevm_arg_inc(mlxdevm);
			err = mlxdevm_argv_str(mlxdevm, &opts->rate_parent_node);
			if (err)
				return err;
			o_found |= MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME;
		} else if (mlxdevm_argv_match(mlxdevm, "noparent") &&
			  (o_all & MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME)) {
			mlxdevm_arg_inc(mlxdevm);
			opts->rate_parent_node = "";
			o_found |= MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME;
		} else {
			pr_err("Unknown option \"%s\"\n",
			       mlxdevm_argv(mlxdevm));
			return -EINVAL;
		}
	}

	opts->present = o_found;

	return mlxdevm_args_finding_required_validate(o_required, o_found);
}

static void
mlxdevm_function_attr_put(struct nlmsghdr *nlh,
			   const struct mlxdevm_opts *opts)
{
	struct nlattr *nest;

	nest = mnl_attr_nest_start(nlh, MLXDEVM_ATTR_PORT_FUNCTION);

	if (opts->present & MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR)
		mnl_attr_put(nlh, MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR,
			     opts->port_function_hw_addr_len,
			     opts->port_function_hw_addr);
	if (opts->present & MLXDEVM_OPT_PORT_FUNCTION_STATE)
		mnl_attr_put_u8(nlh, MLXDEVM_PORT_FN_ATTR_STATE,
				opts->port_fn_state);
	if (opts->present & MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE)
		mnl_attr_put_u8(nlh, MLXDEVM_PORT_FN_ATTR_TRUST_STATE,
				opts->port_fn_trust);
	mnl_attr_nest_end(nlh, nest);
}

static void
mlxdevm_function_cap_attr_put(struct nlmsghdr *nlh,
			      const struct mlxdevm_opts *opts)
{
	struct nlattr *nest;

	nest = mnl_attr_nest_start(nlh, MLXDEVM_ATTR_EXT_PORT_FN_CAP);

	if (opts->present & MLXDEVM_OPT_PORT_FN_CAP_ROCE)
		mnl_attr_put_u8(nlh, MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE,
				opts->port_fn_cap_roce);
	if (opts->present & MLXDEVM_OPT_PORT_FN_CAP_UC_LIST)
		mnl_attr_put_u32(nlh, MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST,
				opts->port_fn_cap_max_uc_list);

	mnl_attr_nest_end(nlh, nest);
}

static void mlxdevm_opts_put(struct nlmsghdr *nlh, struct mlxdevm *mlxdevm)
{
	struct mlxdevm_opts *opts = &mlxdevm->opts;

	if (opts->present & MLXDEVM_OPT_HANDLE) {
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_BUS_NAME,
				  opts->bus_name);
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_NAME, opts->dev_name);
	} else if (opts->present & MLXDEVM_OPT_HANDLEP) {
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_BUS_NAME,
				  opts->bus_name);
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_NAME, opts->dev_name);
		mnl_attr_put_u32(nlh, MLXDEVM_ATTR_PORT_INDEX,
				 opts->port_index);
	} else if (opts->present & MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME) {
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_BUS_NAME,
				  opts->bus_name);
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_DEV_NAME, opts->dev_name);
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_EXT_RATE_NODE_NAME,
				  opts->rate_node_name);
	}

	if (opts->present & (MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR |
			     MLXDEVM_OPT_PORT_FUNCTION_STATE |
			     MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE))
		mlxdevm_function_attr_put(nlh, opts);
	if (opts->present & MLXDEVM_OPT_PORT_FLAVOUR)
		mnl_attr_put_u16(nlh, MLXDEVM_ATTR_PORT_FLAVOUR,
				 opts->port_flavour);
	if (opts->present & MLXDEVM_OPT_PORT_PFNUMBER)
		mnl_attr_put_u16(nlh, MLXDEVM_ATTR_PORT_PCI_PF_NUMBER,
				 opts->port_pfnumber);
	if (opts->present & MLXDEVM_OPT_PORT_SFNUMBER)
		mnl_attr_put_u32(nlh, MLXDEVM_ATTR_PORT_PCI_SF_NUMBER,
				 opts->port_sfnumber);
	if (opts->present & MLXDEVM_OPT_PARAM_NAME)
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_PARAM_NAME,
				  opts->param_name);
	if (opts->present & MLXDEVM_OPT_PARAM_CMODE)
		mnl_attr_put_u8(nlh, MLXDEVM_ATTR_PARAM_VALUE_CMODE,
				opts->cmode);
	if (opts->present & (MLXDEVM_OPT_PORT_FN_CAP_ROCE |
			     MLXDEVM_OPT_PORT_FN_CAP_UC_LIST))
		mlxdevm_function_cap_attr_put(nlh, opts);
	if (opts->present & MLXDEVM_OPT_PORT_CONTROLLER)
		mnl_attr_put_u32(nlh, MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER,
				 opts->port_controller);
	if (opts->present & MLXDEVM_OPT_PORT_FN_RATE_TYPE)
		mnl_attr_put_u16(nlh, MLXDEVM_ATTR_EXT_RATE_TYPE,
				 opts->port_function_rate_type);
	if (opts->present & MLXDEVM_OPT_PORT_FN_RATE_TX_SHARE)
		mnl_attr_put_u64(nlh, MLXDEVM_ATTR_EXT_RATE_TX_SHARE,
				 opts->port_function_rate_tx_share);
	if (opts->present & MLXDEVM_OPT_PORT_FN_RATE_TX_MAX)
		mnl_attr_put_u64(nlh, MLXDEVM_ATTR_EXT_RATE_TX_MAX,
				 opts->port_function_rate_tx_max);
	if (opts->present & MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME)
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME,
				  opts->rate_parent_node);
}

static int mlxdevm_argv_parse_put(struct nlmsghdr *nlh,
				  struct mlxdevm *mlxdevm,
				  uint64_t o_required, uint64_t o_optional)
{
	int err;

	err = mlxdevm_argv_parse(mlxdevm, o_required, o_optional);
	if (err)
		return err;
	mlxdevm_opts_put(nlh, mlxdevm);
	return 0;
}

static void __pr_out_rate_handle_start(struct mlxdevm *mlxdevm,
				       const char *bus_name,
				       const char *dev_name,
				       uint32_t port_index, const char *group_name)
{
	static char buf[64];

	if (group_name)
		sprintf(buf, "%s/%s/%s", bus_name, dev_name, group_name);
	else
		sprintf(buf, "%s/%s/%d", bus_name, dev_name, port_index);

	if (mlxdevm->json_output)
		open_json_object(buf);
	else
		pr_out("%s:", buf);
}

static void pr_out_rate(struct mlxdevm *mlxdevm, struct nlattr **tb)
{
	const char *bus_name, *dev_name, *rate_type_str, *group_name = NULL;
	uint64_t tx_max, tx_share;
	uint32_t port_index;
	uint16_t rate_type;

	if (!tb[MLXDEVM_ATTR_EXT_RATE_TYPE])
		return;

	rate_type = mnl_attr_get_u16(tb[MLXDEVM_ATTR_EXT_RATE_TYPE]);
	bus_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_BUS_NAME]);
	dev_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_NAME]);

	if (rate_type == MLXDEVM_RATE_EXT_TYPE_NODE) {
		group_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_EXT_RATE_NODE_NAME]);
		rate_type_str = "node";
	} else {
		port_index = mnl_attr_get_u32(tb[MLXDEVM_ATTR_PORT_INDEX]);
		rate_type_str = "leaf";
	}

	__pr_out_rate_handle_start(mlxdevm, bus_name, dev_name, port_index, group_name);
	check_indent_newline(mlxdevm);

	print_string(PRINT_ANY, "type", "type %s", rate_type_str);

	if (tb[MLXDEVM_ATTR_EXT_RATE_TX_MAX]) {
		tx_max = mnl_attr_get_u64(tb[MLXDEVM_ATTR_EXT_RATE_TX_MAX]);
		print_uint(PRINT_ANY, "tx_max", " tx_max %u", tx_max);
	}

	if (tb[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]) {
		tx_share = mnl_attr_get_u64(tb[MLXDEVM_ATTR_EXT_RATE_TX_SHARE]);
		print_uint(PRINT_ANY, "tx_share", " tx_share %u", tx_share);
	}

	if (rate_type == MLXDEVM_RATE_EXT_TYPE_LEAF)
		if (tb[MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME])
			print_string(PRINT_ANY, "parent", " parent %s", mnl_attr_get_str(tb[MLXDEVM_ATTR_EXT_RATE_PARENT_NODE_NAME]));

	pr_out_handle_end(mlxdevm);
}

static void cmd_port_function_rate_help(void)
{
	pr_err("Usage: mlxdevm port function rate add DEV/GROUP_NAME\n");
	pr_err("Usage: mlxdevm port function rate del DEV/GROUP_NAME\n");
	pr_err("Usage: mlxdevm port function rate set DEV/GROUP_NAME [ tx_share BW_in_Mbps ] [ tx_max BW_in_Mbps ]\n");
	pr_err("Usage: mlxdevm port function rate set DEV/PORT_INDEX [ tx_share BW_in_Mbps ] [ tx_max BW_in_Mbps ] [parent group_name]\n");
	pr_err("Usage: mlxdevm port function rate set DEV/PORT_INDEX noparent\n");
	pr_err("Usage: mlxdevm port function rate show\n");
	pr_err("Usage: mlxdevm port function rate show DEV/GROUP_NAME\n");
	pr_err("Usage: mlxdevm port function rate show DEV/PORT_INDEX\n");
}

static int cmd_port_function_rate_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct mlxdevm *mlxdevm = data;
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	pr_out_rate(mlxdevm, tb);
	return MNL_CB_OK;
}

static int cmd_port_function_rate_show(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	mlxdevm_arg_inc(mlxdevm);

	if (mlxdevm_argc(mlxdevm) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_EXT_RATE_GET, flags);

	if (mlxdevm_argc(mlxdevm) > 0) {
		err = mlxdevm_argv_parse_put(nlh, mlxdevm,
					     MLXDEVM_OPT_HANDLEP |
					     MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME,
					     0);
		if (err)
			return err;
	}

	pr_out_section_start(mlxdevm, "rate");
	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh,
				     cmd_port_function_rate_show_cb,
				     mlxdevm);
	pr_out_section_end(mlxdevm);
	return err;
}

static int cmd_port_function_rate_set(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err = 0;

	mlxdevm_arg_inc(mlxdevm);

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_EXT_RATE_SET,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm,
				     MLXDEVM_OPT_HANDLEP | MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME,
				     MLXDEVM_OPT_PORT_FN_RATE_TX_SHARE |
				     MLXDEVM_OPT_PORT_FN_RATE_TX_MAX |
				     MLXDEVM_OPT_PORT_FN_RATE_PARENT_NODE_NAME);

	if (err) {
		cmd_port_function_rate_help();
		return err;
	}

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port_function_rate_add(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err = 0;

	mlxdevm_arg_inc(mlxdevm);

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_EXT_RATE_NEW,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm,
				     MLXDEVM_OPT_HANDLEP | MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME, 0);

	if (err) {
		cmd_port_function_rate_help();
		return err;
	}

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port_function_rate_del(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err = 0;

	mlxdevm_arg_inc(mlxdevm);

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_EXT_RATE_DEL,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm,
				     MLXDEVM_OPT_HANDLEP | MLXDEVM_OPT_PORT_FN_RATE_NODE_NAME, 0);

	if (err) {
		cmd_port_function_rate_help();
		return err;
	}

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port_function_rate(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_no_arg(mlxdevm)) {
		cmd_port_function_rate_help();
		return 0;
	}

	if (mlxdevm_argv_match(mlxdevm, "set")) {
		cmd_port_function_rate_set(mlxdevm);
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "show")) {
		cmd_port_function_rate_show(mlxdevm);
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "add")) {
		cmd_port_function_rate_add(mlxdevm);
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "del")) {
		cmd_port_function_rate_del(mlxdevm);
		return 0;
	}

	cmd_port_function_rate_help();
	return 0;
}

static void cmd_dev_help(void)
{
	pr_err("Usage: mlxdevm dev show [ DEV ]\n");
	pr_err("       mlxdevm dev param set DEV name PARAMETER value VALUE cmode { permanent | driverinit | runtime }\n");
	pr_err("       mlxdevm dev param show [DEV name PARAMETER]\n");
}

static bool cmp_arr_last_handle(struct mlxdevm *mlxdevm,
				const char *bus_name, const char *dev_name)
{
	if (!mlxdevm->arr_last.present)
		return false;
	return strcmp(mlxdevm->arr_last.bus_name, bus_name) == 0 &&
	       strcmp(mlxdevm->arr_last.dev_name, dev_name) == 0;
}

static void arr_last_handle_set(struct mlxdevm *mlxdevm,
				const char *bus_name, const char *dev_name)
{
	mlxdevm->arr_last.present = true;
	free(mlxdevm->arr_last.dev_name);
	free(mlxdevm->arr_last.bus_name);
	mlxdevm->arr_last.bus_name = strdup(bus_name);
	mlxdevm->arr_last.dev_name = strdup(dev_name);
}

static bool should_arr_last_handle_start(struct mlxdevm *mlxdevm,
					 const char *bus_name,
					 const char *dev_name)
{
	return !cmp_arr_last_handle(mlxdevm, bus_name, dev_name);
}

static bool should_arr_last_handle_end(struct mlxdevm *mlxdevm,
				       const char *bus_name,
				       const char *dev_name)
{
	return mlxdevm->arr_last.present &&
	       !cmp_arr_last_handle(mlxdevm, bus_name, dev_name);
}

static void __pr_out_handle_start(struct mlxdevm *mlxdevm,
				  struct nlattr **tb, bool content, bool array)
{
	const char *bus_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_BUS_NAME]);
	const char *dev_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_NAME]);
	char buf[64];

	sprintf(buf, "%s/%s", bus_name, dev_name);

	if (mlxdevm->json_output) {
		if (array) {
			if (should_arr_last_handle_end(mlxdevm, bus_name,
						       dev_name))
				close_json_array(PRINT_JSON, NULL);
			if (should_arr_last_handle_start(mlxdevm, bus_name,
							 dev_name)) {
				open_json_array(PRINT_JSON, buf);
				open_json_object(NULL);
				arr_last_handle_set(mlxdevm, bus_name,
						    dev_name);
			} else {
				open_json_object(NULL);
			}
		} else {
			open_json_object(buf);
		}
	} else {
		if (array) {
			if (should_arr_last_handle_end(mlxdevm, bus_name,
						       dev_name))
				__pr_out_indent_dec();
			if (should_arr_last_handle_start(mlxdevm, bus_name,
							 dev_name)) {
				pr_out("%s%s", buf, content ? ":" : "");
				__pr_out_newline();
				__pr_out_indent_inc();
				arr_last_handle_set(mlxdevm, bus_name,
						    dev_name);
			}
		} else {
			pr_out("%s%s", buf, content ? ":" : "");
		}
	}
}

static void pr_out_handle_start_arr(struct mlxdevm *mlxdevm, struct nlattr **tb)
{
	__pr_out_handle_start(mlxdevm, tb, true, true);
}

static void pr_out_handle_end(struct mlxdevm *mlxdevm)
{
	if (mlxdevm->json_output)
		close_json_object();
	else
		__pr_out_newline();
}

static void pr_out_handle(struct mlxdevm *mlxdevm, struct nlattr **tb)
{
	__pr_out_handle_start(mlxdevm, tb, false, false);
	pr_out_handle_end(mlxdevm);
}

static bool cmp_arr_last_port_handle(struct mlxdevm *mlxdevm,
				     const char *bus_name,
				     const char *dev_name, uint32_t port_index)
{
	return cmp_arr_last_handle(mlxdevm, bus_name, dev_name) &&
	       mlxdevm->arr_last.port_index == port_index;
}

static void arr_last_port_handle_set(struct mlxdevm *mlxdevm,
				     const char *bus_name,
				     const char *dev_name, uint32_t port_index)
{
	arr_last_handle_set(mlxdevm, bus_name, dev_name);
	mlxdevm->arr_last.port_index = port_index;
}

static bool should_arr_last_port_handle_start(struct mlxdevm *mlxdevm,
					      const char *bus_name,
					      const char *dev_name,
					      uint32_t port_index)
{
	return !cmp_arr_last_port_handle(mlxdevm, bus_name, dev_name,
					 port_index);
}

static bool should_arr_last_port_handle_end(struct mlxdevm *mlxdevm,
					    const char *bus_name,
					    const char *dev_name,
					    uint32_t port_index)
{
	return mlxdevm->arr_last.present &&
	       !cmp_arr_last_port_handle(mlxdevm, bus_name, dev_name,
					 port_index);
}

static void __pr_out_port_handle_start(struct mlxdevm *mlxdevm,
				       const char *bus_name,
				       const char *dev_name,
				       uint32_t port_index, bool try_nice,
				       bool array)
{
	static char buf[64];
	char *ifname = NULL;

	if (mlxdevm->no_nice_names || !try_nice ||
	    ifname_map_rev_lookup(mlxdevm, bus_name, dev_name,
				  port_index, &ifname) != 0)
		sprintf(buf, "%s/%s/%d", bus_name, dev_name, port_index);
	else
		sprintf(buf, "%s", ifname);

	if (mlxdevm->json_output) {
		if (array) {
			if (should_arr_last_port_handle_end(mlxdevm, bus_name,
							    dev_name,
							    port_index))
				close_json_array(PRINT_JSON, NULL);
			if (should_arr_last_port_handle_start(mlxdevm,
							      bus_name,
							      dev_name,
							      port_index)) {
				open_json_array(PRINT_JSON, buf);
				open_json_object(NULL);
				arr_last_port_handle_set(mlxdevm, bus_name,
							 dev_name, port_index);
			} else {
				open_json_object(NULL);
			}
		} else {
			open_json_object(buf);
		}
	} else {
		if (array) {
			if (should_arr_last_port_handle_end(mlxdevm, bus_name,
							    dev_name,
							    port_index))
				__pr_out_indent_dec();
			if (should_arr_last_port_handle_start(mlxdevm,
							      bus_name,
							      dev_name,
							      port_index)) {
				pr_out("%s:", buf);
				__pr_out_newline();
				__pr_out_indent_inc();
				arr_last_port_handle_set(mlxdevm, bus_name,
							 dev_name, port_index);
			}
		} else {
			pr_out("%s:", buf);
		}
	}
}

static void pr_out_port_handle_start(struct mlxdevm *mlxdevm,
				     struct nlattr **tb, bool try_nice)
{
	const char *bus_name;
	const char *dev_name;
	uint32_t port_index;

	bus_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_BUS_NAME]);
	dev_name = mnl_attr_get_str(tb[MLXDEVM_ATTR_DEV_NAME]);
	port_index = mnl_attr_get_u32(tb[MLXDEVM_ATTR_PORT_INDEX]);
	__pr_out_port_handle_start(mlxdevm, bus_name, dev_name, port_index,
				   try_nice, false);
}

static const char *param_cmode_name(uint8_t cmode)
{
	switch (cmode) {
	case MLXDEVM_PARAM_CMODE_RUNTIME:
		return PARAM_CMODE_RUNTIME_STR;
	case MLXDEVM_PARAM_CMODE_DRIVERINIT:
		return PARAM_CMODE_DRIVERINIT_STR;
	default: return "<unknown type>";
	}
}

struct param_val_conv {
	const char *name;
	const char *vstr;
	uint32_t vuint;
};

static bool param_val_conv_exists(const struct param_val_conv *param_val_conv,
				  uint32_t len, const char *name)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		if (!strcmp(param_val_conv[i].name, name))
			return true;

	return false;
}

static int
param_val_conv_uint_get(const struct param_val_conv *param_val_conv,
			uint32_t len, const char *name, const char *vstr,
			uint32_t *vuint)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		if (!strcmp(param_val_conv[i].name, name) &&
		    !strcmp(param_val_conv[i].vstr, vstr)) {
			*vuint = param_val_conv[i].vuint;
			return 0;
		}

	return -ENOENT;
}

static int
param_val_conv_str_get(const struct param_val_conv *param_val_conv,
		       uint32_t len, const char *name, uint32_t vuint,
		       const char **vstr)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		if (!strcmp(param_val_conv[i].name, name) &&
		    param_val_conv[i].vuint == vuint) {
			*vstr = param_val_conv[i].vstr;
			return 0;
		}

	return -ENOENT;
}

static const struct param_val_conv param_val_conv[] = {
	{
		.name = "fw_load_policy",
		.vstr = "driver",
		.vuint = MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_DRIVER,
	},
	{
		.name = "fw_load_policy",
		.vstr = "flash",
		.vuint = MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_FLASH,
	},
	{
		.name = "fw_load_policy",
		.vstr = "disk",
		.vuint = MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_DISK,
	},
	{
		.name = "reset_dev_on_drv_probe",
		.vstr = "unknown",
		.vuint = MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_UNKNOWN,
	},
	{
		.name = "fw_load_policy",
		.vstr = "unknown",
		.vuint = MLXDEVM_PARAM_FW_LOAD_POLICY_VALUE_UNKNOWN,
	},
	{
		.name = "reset_dev_on_drv_probe",
		.vstr = "always",
		.vuint = MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_ALWAYS,
	},
	{
		.name = "reset_dev_on_drv_probe",
		.vstr = "never",
		.vuint = MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_NEVER,
	},
	{
		.name = "reset_dev_on_drv_probe",
		.vstr = "disk",
		.vuint = MLXDEVM_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_DISK,
	},
};

#define BITS_PER_BYTE 8
/*
 * Returns human readable representation of the given set. The output format is
 * a list of numbers with ranges (for example, "0,1,3-9").
 */
static char *list_create(char *str, size_t len, uint8_t list_type,
			 uint8_t *list, size_t list_size)
{
        size_t i;
        char *ptr = str;
        int entry_made = 0;
	uint64_t num = 0;

        for (i = 0; i < list_size; i+= list_type) {
		memcpy(&num, &list[i], list_type);
		{
			int rlen;
			size_t j, b, run = 0;
			entry_made = 1;
			for (j = i + list_type; j < list_size; j += list_type) {
				b = 0;
				memcpy(&b, &list[j], list_type);
				if (b == (num + run + 1))
					run++;
				else
					break;
			}
			if (!run)
				rlen = snprintf(ptr, len, "%zu,", num);
			else if (run == 1) {
				rlen = snprintf(ptr, len, "%zu,%zu,", num, num + 1);
				i += list_type;
			} else {
				rlen = snprintf(ptr, len, "%zu-%zu,", num, num + run);
				i += run * list_type;
			}
			if (rlen < 0 || (size_t) rlen >= len)
				return NULL;
			ptr += rlen;
			len -= rlen;
		}
        }
        ptr -= entry_made;
        *ptr = '\0';

        return str;
}

#define PARAM_VAL_CONV_LEN ARRAY_SIZE(param_val_conv)

static void pr_out_param_value(struct mlxdevm *mlxdevm, const char *nla_name,
			       int nla_type, struct nlattr *nl)
{
	struct nlattr *nla_value[MLXDEVM_ATTR_MAX + 1] = {};
	struct nlattr *val_attr;
	const char *vstr;
	bool conv_exists;
	void *data;
	SPRINT_BUF(num_list);
	uint32_t len;
	int err;
	uint8_t type;

	err = mnl_attr_parse_nested(nl, attr_cb, nla_value);
	if (err != MNL_CB_OK)
		return;

	if (!nla_value[MLXDEVM_ATTR_PARAM_VALUE_CMODE] ||
	    (nla_type != MNL_TYPE_FLAG &&
	     !nla_value[MLXDEVM_ATTR_PARAM_VALUE_DATA]))
		return;

	check_indent_newline(mlxdevm);
	print_string(PRINT_ANY, "cmode", "cmode %s",
		     param_cmode_name(mnl_attr_get_u8(nla_value[MLXDEVM_ATTR_PARAM_VALUE_CMODE])));

	val_attr = nla_value[MLXDEVM_ATTR_PARAM_VALUE_DATA];

	conv_exists = param_val_conv_exists(param_val_conv, PARAM_VAL_CONV_LEN,
					    nla_name);

	switch (nla_type) {
	case MNL_TYPE_U8:
		if (conv_exists) {
			err = param_val_conv_str_get(param_val_conv,
						     PARAM_VAL_CONV_LEN,
						     nla_name,
						     mnl_attr_get_u8(val_attr),
						     &vstr);
			if (err)
				return;
			print_string(PRINT_ANY, "value", " value %s", vstr);
		} else {
			print_uint(PRINT_ANY, "value", " value %u",
				   mnl_attr_get_u8(val_attr));
		}
		break;
	case MNL_TYPE_U16:
		if (conv_exists) {
			err = param_val_conv_str_get(param_val_conv,
						     PARAM_VAL_CONV_LEN,
						     nla_name,
						     mnl_attr_get_u16(val_attr),
						     &vstr);
			if (err)
				return;
			print_string(PRINT_ANY, "value", " value %s", vstr);
		} else {
			print_uint(PRINT_ANY, "value", " value %u",
				   mnl_attr_get_u16(val_attr));
		}
		break;
	case MNL_TYPE_U32:
		if (conv_exists) {
			err = param_val_conv_str_get(param_val_conv,
						     PARAM_VAL_CONV_LEN,
						     nla_name,
						     mnl_attr_get_u32(val_attr),
						     &vstr);
			if (err)
				return;
			print_string(PRINT_ANY, "value", " value %s", vstr);
		} else {
			print_uint(PRINT_ANY, "value", " value %u",
				   mnl_attr_get_u32(val_attr));
		}
		break;
	case MNL_TYPE_STRING:
		print_string(PRINT_ANY, "value", " value %s",
			     mnl_attr_get_str(val_attr));
		break;
	case MNL_TYPE_FLAG:
		print_bool(PRINT_ANY, "value", " value %s", val_attr);
		break;
	case MNL_TYPE_NESTED:
		type = mnl_attr_get_u8(nla_value[MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE]);
		data = mnl_attr_get_payload(val_attr);
		len = mnl_attr_get_payload_len(val_attr);

		print_string(PRINT_ANY, "value", " value %s",
			     list_create(num_list, sizeof(num_list), type, data,
					 len));
		break;
	}
}

static void pr_out_param(struct mlxdevm *mlxdevm, struct nlattr **tb, bool array)
{
	struct nlattr *nla_param[MLXDEVM_ATTR_MAX + 1] = {};
	struct nlattr *param_value_attr;
	const char *nla_name;
	int nla_type;
	int err;

	err = mnl_attr_parse_nested(tb[MLXDEVM_ATTR_PARAM], attr_cb, nla_param);
	if (err != MNL_CB_OK)
		return;
	if (!nla_param[MLXDEVM_ATTR_PARAM_NAME] ||
	    !nla_param[MLXDEVM_ATTR_PARAM_TYPE] ||
	    !nla_param[MLXDEVM_ATTR_PARAM_VALUES_LIST])
		return;

	if (array)
		pr_out_handle_start_arr(mlxdevm, tb);
	else
		__pr_out_handle_start(mlxdevm, tb, true, false);

	nla_type = mnl_attr_get_u8(nla_param[MLXDEVM_ATTR_PARAM_TYPE]);

	nla_name = mnl_attr_get_str(nla_param[MLXDEVM_ATTR_PARAM_NAME]);
	check_indent_newline(mlxdevm);
	print_string(PRINT_ANY, "name", "name %s ", nla_name);
	if (!nla_param[MLXDEVM_ATTR_PARAM_GENERIC])
		print_string(PRINT_ANY, "type", "type %s", "driver-specific");
	else
		print_string(PRINT_ANY, "type", "type %s", "generic");

	pr_out_array_start(mlxdevm, "values");
	mnl_attr_for_each_nested(param_value_attr,
				 nla_param[MLXDEVM_ATTR_PARAM_VALUES_LIST]) {
		pr_out_entry_start(mlxdevm);
		pr_out_param_value(mlxdevm, nla_name, nla_type, param_value_attr);
		pr_out_entry_end(mlxdevm);
	}
	pr_out_array_end(mlxdevm);
	pr_out_handle_end(mlxdevm);
}

struct param_ctx {
	struct mlxdevm *mlxdevm;
	int nla_type;
	union {
		uint8_t vu8;
		uint16_t vu16;
		uint32_t vu32;
		const char *vstr;
		bool vbool;
		uint16_t *vu16arr;
	} value;
	int array_type;
};

static int cmd_dev_param_set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *nla_param[MLXDEVM_ATTR_MAX + 1] = {};
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct nlattr *param_value_attr;
	enum mlxdevm_param_cmode cmode;
	struct param_ctx *ctx = data;
	struct mlxdevm *mlxdevm = ctx->mlxdevm;
	int nla_type;
	int err;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME] ||
	    !tb[MLXDEVM_ATTR_PARAM])
		return MNL_CB_ERROR;

	err = mnl_attr_parse_nested(tb[MLXDEVM_ATTR_PARAM], attr_cb, nla_param);
	if (err != MNL_CB_OK)
		return MNL_CB_ERROR;

	if (!nla_param[MLXDEVM_ATTR_PARAM_TYPE] ||
	    !nla_param[MLXDEVM_ATTR_PARAM_VALUES_LIST])
		return MNL_CB_ERROR;

	nla_type = mnl_attr_get_u8(nla_param[MLXDEVM_ATTR_PARAM_TYPE]);
	mnl_attr_for_each_nested(param_value_attr,
				 nla_param[MLXDEVM_ATTR_PARAM_VALUES_LIST]) {
		struct nlattr *nla_value[MLXDEVM_ATTR_MAX + 1] = {};
		struct nlattr *val_attr;

		err = mnl_attr_parse_nested(param_value_attr,
					    attr_cb, nla_value);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		if (!nla_value[MLXDEVM_ATTR_PARAM_VALUE_CMODE] ||
		    (nla_type != MNL_TYPE_FLAG &&
		     !nla_value[MLXDEVM_ATTR_PARAM_VALUE_DATA]))
			return MNL_CB_ERROR;

		cmode = mnl_attr_get_u8(nla_value[MLXDEVM_ATTR_PARAM_VALUE_CMODE]);
		if (cmode == mlxdevm->opts.cmode) {
			val_attr = nla_value[MLXDEVM_ATTR_PARAM_VALUE_DATA];
			switch (nla_type) {
			case MNL_TYPE_U8:
				ctx->value.vu8 = mnl_attr_get_u8(val_attr);
				break;
			case MNL_TYPE_U16:
				ctx->value.vu16 = mnl_attr_get_u16(val_attr);
				break;
			case MNL_TYPE_U32:
				ctx->value.vu32 = mnl_attr_get_u32(val_attr);
				break;
			case MNL_TYPE_STRING:
				ctx->value.vstr = mnl_attr_get_str(val_attr);
				break;
			case MNL_TYPE_FLAG:
				ctx->value.vbool = val_attr ? true : false;
				break;
			case MNL_TYPE_NESTED:
				ctx->array_type = mnl_attr_get_u8(nla_value[MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE]);
				switch (ctx->array_type) {
				case MLXDEVM_PARAM_ARRAY_TYPE_U16:
					ctx->value.vu16arr = mnl_attr_get_payload(val_attr);
					break;
				}
				break;
			}
			break;
		}
	}
	ctx->nla_type = nla_type;
	return MNL_CB_OK;
}

#define MAX_NUM_LIST_CHARS 128
static int list_parse(const char *str, uint8_t list_type ,uint8_t *list,
		      uint32_t *len)
{
	char src[MAX_NUM_LIST_CHARS];
	char range_delim[] = "-";
	uint16_t index = 0;
	char delim[] = ",";
	char *start, *end;
	char *token;
	char *p;
	int err;

	if (strlen(str) > MAX_NUM_LIST_CHARS)
		return -EINVAL;
	strcpy(src, str);
	token = strtok_r(src, delim, &p);

	while(token != NULL) {
		uint64_t a; /* beginning of range */
		uint64_t b = 0; /* end of range */
		uint64_t k;

		start = strtok(token, range_delim);
		err = strtouint64_t(start, &a);
		if (err)
			return err;
		end = strtok(NULL, range_delim);
		if (end != NULL) {
			err = strtouint64_t(end, &b);
			if (err)
				return err;
		}
		if (b < a)
			b = a;
		for (k = a; k <= b; k++) {
			memcpy(&list[index], &k, list_type);
			index += list_type;
		}
		token = strtok_r(NULL, delim, &p);
	}
	if (index / list_type > 8)
		return -EINVAL;
	*len = index;
	return 0;
}

static int cmd_dev_param_set(struct mlxdevm *mlxdevm)
{
	uint16_t val_vu16arr[64] = {};
	struct param_ctx ctx = {};
	struct nlmsghdr *nlh;
	bool conv_exists;
	uint32_t val_u32 = 0;
	uint32_t vu16arr_len = 0;
	uint16_t val_u16;
	uint8_t val_u8;
	bool val_bool;
	int err;

	err = mlxdevm_argv_parse(mlxdevm, MLXDEVM_OPT_HANDLE |
				 MLXDEVM_OPT_PARAM_NAME |
				 MLXDEVM_OPT_PARAM_VALUE |
				 MLXDEVM_OPT_PARAM_CMODE, 0);
	if (err)
		return err;

	/* Get value type */
	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg, MLXDEVM_CMD_PARAM_GET,
			       NLM_F_REQUEST | NLM_F_ACK);
	mlxdevm_opts_put(nlh, mlxdevm);

	ctx.mlxdevm = mlxdevm;
	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, cmd_dev_param_set_cb, &ctx);
	if (err)
		return err;

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg, MLXDEVM_CMD_PARAM_SET,
			       NLM_F_REQUEST | NLM_F_ACK);
	mlxdevm_opts_put(nlh, mlxdevm);

	conv_exists = param_val_conv_exists(param_val_conv, PARAM_VAL_CONV_LEN,
					    mlxdevm->opts.param_name);

	mnl_attr_put_u8(nlh, MLXDEVM_ATTR_PARAM_TYPE, ctx.nla_type);
	switch (ctx.nla_type) {
	case MNL_TYPE_U8:
		if (conv_exists) {
			err = param_val_conv_uint_get(param_val_conv,
						      PARAM_VAL_CONV_LEN,
						      mlxdevm->opts.param_name,
						      mlxdevm->opts.param_value,
						      &val_u32);
			val_u8 = val_u32;
		} else {
			err = strtouint8_t(mlxdevm->opts.param_value, &val_u8);
		}
		if (err)
			goto err_param_value_parse;
		if (val_u8 == ctx.value.vu8)
			return 0;
		mnl_attr_put_u8(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA, val_u8);
		break;
	case MNL_TYPE_U16:
		if (conv_exists) {
			err = param_val_conv_uint_get(param_val_conv,
						      PARAM_VAL_CONV_LEN,
						      mlxdevm->opts.param_name,
						      mlxdevm->opts.param_value,
						      &val_u32);
			val_u16 = val_u32;
		} else {
			err = strtouint16_t(mlxdevm->opts.param_value, &val_u16);
		}
		if (err)
			goto err_param_value_parse;
		if (val_u16 == ctx.value.vu16)
			return 0;
		mnl_attr_put_u16(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA, val_u16);
		break;
	case MNL_TYPE_U32:
		if (conv_exists)
			err = param_val_conv_uint_get(param_val_conv,
						      PARAM_VAL_CONV_LEN,
						      mlxdevm->opts.param_name,
						      mlxdevm->opts.param_value,
						      &val_u32);
		else
			err = strtouint32_t(mlxdevm->opts.param_value, &val_u32);
		if (err)
			goto err_param_value_parse;
		if (val_u32 == ctx.value.vu32)
			return 0;
		mnl_attr_put_u32(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA, val_u32);
		break;
	case MNL_TYPE_FLAG:
		err = strtobool(mlxdevm->opts.param_value, &val_bool);
		if (err)
			goto err_param_value_parse;
		if (val_bool == ctx.value.vbool)
			return 0;
		if (val_bool)
			mnl_attr_put(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA,
				     0, NULL);
		break;
	case MNL_TYPE_STRING:
		mnl_attr_put_strz(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA,
				  mlxdevm->opts.param_value);
		if (!strcmp(mlxdevm->opts.param_value, ctx.value.vstr))
			return 0;
		break;
	case MNL_TYPE_NESTED:
		if (!ctx.array_type) {
			pr_err("No array type received from kernel\n");
			return -EINVAL;
		}
		mnl_attr_put_u8(nlh, MLXDEVM_ATTR_EXT_PARAM_ARRAY_TYPE,
				ctx.array_type);
		err = list_parse(mlxdevm->opts.param_value, ctx.array_type,
				 (uint8_t*)val_vu16arr, &vu16arr_len);
		if (err)
			goto err_param_value_parse;
		mnl_attr_put(nlh, MLXDEVM_ATTR_PARAM_VALUE_DATA,
			     vu16arr_len, val_vu16arr);
		break;
	default:
		printf("Value type not supported\n");
		return -ENOTSUP;
	}
	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);

err_param_value_parse:
	pr_err("Value \"%s\" is not a number or not within range\n",
	       mlxdevm->opts.param_value);
	return err;
}

static int cmd_dev_param_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct mlxdevm *mlxdevm = data;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME] ||
	    !tb[MLXDEVM_ATTR_PARAM])
		return MNL_CB_ERROR;
	pr_out_param(mlxdevm, tb, true);
	return MNL_CB_OK;
}

static int cmd_dev_param_show(struct mlxdevm *mlxdevm)
{
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	struct nlmsghdr *nlh;
	int err;

	if (mlxdevm_argc(mlxdevm) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg, MLXDEVM_CMD_PARAM_GET,
					  flags);

	if (mlxdevm_argc(mlxdevm) > 0) {
		err = mlxdevm_argv_parse_put(nlh, mlxdevm, MLXDEVM_OPT_HANDLE |
					     MLXDEVM_OPT_PARAM_NAME, 0);
		if (err)
			return err;
	}

	pr_out_section_start(mlxdevm, "param");
	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, cmd_dev_param_show_cb,
				     mlxdevm);
	pr_out_section_end(mlxdevm);
	return err;
}

static int cmd_dev_param(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argv_match(mlxdevm, "help")) {
		cmd_dev_help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "show") ||
		   mlxdevm_argv_match(mlxdevm, "list") ||
		   mlxdevm_no_arg(mlxdevm)) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_dev_param_show(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "set")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_dev_param_set(mlxdevm);
	}
	pr_err("Command \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static void pr_out_dev(struct mlxdevm *mlxdevm, struct nlattr **tb)
{
	pr_out_handle(mlxdevm, tb);
}

static int cmd_dev_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct mlxdevm *mlxdevm = data;
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	pr_out_dev(mlxdevm, tb);
	return MNL_CB_OK;
}

static int cmd_dev_show(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (mlxdevm_argc(mlxdevm) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg, MLXDEVM_CMD_DEV_GET,
					  flags);

	if (mlxdevm_argc(mlxdevm) > 0) {
		err = mlxdevm_argv_parse_put(nlh, mlxdevm,
					     MLXDEVM_OPT_HANDLE, 0);
		if (err)
			return err;
	}

	pr_out_section_start(mlxdevm, "dev");
	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, cmd_dev_show_cb,
				     mlxdevm);
	pr_out_section_end(mlxdevm);
	return err;
}

static int cmd_dev(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argv_match(mlxdevm, "help")) {
		cmd_dev_help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "show") ||
		   mlxdevm_argv_match(mlxdevm, "list") ||
		   mlxdevm_no_arg(mlxdevm)) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_dev_show(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "param")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_dev_param(mlxdevm);
	}
	pr_err("Command \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static void cmd_port_help(void)
{
	pr_err("Usage: mlxdevm port show [ DEV/PORT_INDEX ]\n");
	pr_err("       mlxdevm port function set DEV/PORT_INDEX [ hw_addr ADDR ] [ state STATE ] trust {on | off}\n");
	pr_err("       mlxdevm port add DEV/PORT_INDEX flavour FLAVOUR pfnum PFNUM [ sfnum SFNUM ] [ controller CNUM ]\n");
	pr_err("       mlxdevm port del DEV/PORT_INDEX\n");
	pr_err("       mlxdevm port function cap set DEV/PORT_INDEX [ roce TRUE/FALSE ] [ max_uc_macs VAL ]\n");
}

static const char *port_type_name(uint32_t type)
{
	switch (type) {
	case MLXDEVM_PORT_TYPE_NOTSET: return "notset";
	case MLXDEVM_PORT_TYPE_AUTO: return "auto";
	case MLXDEVM_PORT_TYPE_ETH: return "eth";
	case MLXDEVM_PORT_TYPE_IB: return "ib";
	default: return "<unknown type>";
	}
}

static const char *port_fn_trust(uint8_t trust)
{
	const char *str;

	str = str_map_lookup_u8(port_fn_trust_map, trust);
	return str ? str : "<unknown state>";
}

static const char *port_flavour_name(uint16_t flavour)
{
	const char *str;

	str = str_map_lookup_u16(port_flavour_map, flavour);
	return str ? str : "<unknown flavour>";
}

static void pr_out_port_pfsf_num(struct mlxdevm *mlxdevm,
				 struct nlattr **tb)
{
	uint16_t fn_num;

	if (tb[MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER])
		print_uint(PRINT_ANY, "controller", " controller %u",
			   mnl_attr_get_u32(
				   tb[MLXDEVM_ATTR_PORT_CONTROLLER_NUMBER]));
	if (tb[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER]) {
		fn_num = mnl_attr_get_u16(tb[MLXDEVM_ATTR_PORT_PCI_PF_NUMBER]);
		print_uint(PRINT_ANY, "pfnum", " pfnum %u", fn_num);
	}
	if (tb[MLXDEVM_ATTR_PORT_PCI_SF_NUMBER]) {
		fn_num = mnl_attr_get_u32(tb[MLXDEVM_ATTR_PORT_PCI_SF_NUMBER]);
		print_uint(PRINT_ANY, "sfnum", " sfnum %u", fn_num);
	}
	if (tb[MLXDEVM_ATTR_PORT_EXTERNAL]) {
		uint8_t external;

		external = mnl_attr_get_u8(tb[MLXDEVM_ATTR_PORT_EXTERNAL]);
		print_bool(PRINT_ANY, "external", " external %s", external);
	}
}

static const char *port_fn_state(uint8_t state)
{
	const char *str;

	str = str_map_lookup_u8(port_fn_state_map, state);
	return str ? str : "<unknown state>";
}

static const char *port_fn_opstate(uint8_t state)
{
	const char *str;

	str = str_map_lookup_u8(port_fn_opstate_map, state);
	return str ? str : "<unknown state>";
}

static const char *port_fn_cap_roce(uint8_t roce)
{
	const char *str;

	str = str_map_lookup_u8(port_fn_cap_roce_map, roce);
	return str ? str : "<unknown state>";
}

static void pr_out_port_function(struct mlxdevm *mlxdevm,
				 struct nlattr **tb_port)
{
	struct nlattr *tb[MLXDEVM_PORT_FUNCTION_ATTR_MAX + 1] = {};
	unsigned char *data;
	SPRINT_BUF(hw_addr);
	uint32_t len;
	int err;

	if (!tb_port[MLXDEVM_ATTR_PORT_FUNCTION])
		return;

	err = mnl_attr_parse_nested(tb_port[MLXDEVM_ATTR_PORT_FUNCTION],
				    function_attr_cb, tb);
	if (err != MNL_CB_OK)
		return;

	pr_out_object_start(mlxdevm, "function");
	check_indent_newline(mlxdevm);

	if (tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR]) {
		len = mnl_attr_get_payload_len(
				tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR]);
		data = mnl_attr_get_payload(
				tb[MLXDEVM_PORT_FUNCTION_ATTR_HW_ADDR]);

		print_string(PRINT_ANY, "hw_addr", "hw_addr %s",
			     ll_addr_n2a(data, len, 0, hw_addr,
				         sizeof(hw_addr)));
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_STATE]) {
		uint8_t state;

		state = mnl_attr_get_u8(tb[MLXDEVM_PORT_FN_ATTR_STATE]);

		print_string(PRINT_ANY, "state", " state %s",
			     port_fn_state(state));
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_OPSTATE]) {
		uint8_t state;

		state = mnl_attr_get_u8(tb[MLXDEVM_PORT_FN_ATTR_OPSTATE]);

		print_string(PRINT_ANY, "opstate", " opstate %s",
			     port_fn_opstate(state));
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE]) {
		uint8_t roce;

		roce = mnl_attr_get_u8(tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_ROCE]);

		print_string(PRINT_ANY, "roce", " roce %s",
			     port_fn_cap_roce(roce));
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST]) {
		uint32_t max_uc_macs;

		max_uc_macs = mnl_attr_get_u32(tb[MLXDEVM_PORT_FN_ATTR_EXT_CAP_UC_LIST]);
		print_uint(PRINT_ANY, "max_uc_macs", " max_uc_macs %u", max_uc_macs);
	}
	if (tb[MLXDEVM_PORT_FN_ATTR_TRUST_STATE]) {
		uint8_t trust;

		trust = mnl_attr_get_u8(tb[MLXDEVM_PORT_FN_ATTR_TRUST_STATE]);

		print_string(PRINT_ANY, "trust", " trust %s", port_fn_trust(trust));
	}

	if (!mlxdevm->json_output)
		__pr_out_indent_dec();
	pr_out_object_end(mlxdevm);
}

static void pr_out_port(struct mlxdevm *mlxdevm, struct nlattr **tb)
{
	struct nlattr *pt_attr = tb[MLXDEVM_ATTR_PORT_TYPE];

	pr_out_port_handle_start(mlxdevm, tb, false);
	check_indent_newline(mlxdevm);
	if (pt_attr) {
		uint16_t port_type = mnl_attr_get_u16(pt_attr);

		print_string(PRINT_ANY, "type", "type %s",
			     port_type_name(port_type));
	}
	if (tb[MLXDEVM_ATTR_PORT_NETDEV_NAME]) {
		print_string(PRINT_ANY, "netdev", " netdev %s",
			     mnl_attr_get_str(tb[MLXDEVM_ATTR_PORT_NETDEV_NAME]));
	}
	if (tb[MLXDEVM_ATTR_PORT_IBDEV_NAME]) {
		print_string(PRINT_ANY, "ibdev", " ibdev %s",
			     mnl_attr_get_str(tb[MLXDEVM_ATTR_PORT_IBDEV_NAME]));
		}
	if (tb[MLXDEVM_ATTR_PORT_FLAVOUR]) {
		uint16_t port_flavour =
				mnl_attr_get_u16(tb[MLXDEVM_ATTR_PORT_FLAVOUR]);

		print_string(PRINT_ANY, "flavour", " flavour %s",
			     port_flavour_name(port_flavour));

		switch (port_flavour) {
		case MLXDEVM_PORT_FLAVOUR_PCI_PF:
		case MLXDEVM_PORT_FLAVOUR_PCI_VF:
		case MLXDEVM_PORT_FLAVOUR_PCI_SF:
			pr_out_port_pfsf_num(mlxdevm, tb);
			break;
		default:
			break;
		}
	}
	if (tb[MLXDEVM_ATTR_PORT_NUMBER]) {
		uint32_t port_number;

		port_number = mnl_attr_get_u32(tb[MLXDEVM_ATTR_PORT_NUMBER]);
		print_uint(PRINT_ANY, "port", " port %u", port_number);
	}
	pr_out_port_function(mlxdevm, tb);
	pr_out_handle_end(mlxdevm);
}

static int cmd_port_show_cb(const struct nlmsghdr *nlh, void *data)
{
	struct mlxdevm *mlxdevm = data;
	struct nlattr *tb[MLXDEVM_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[MLXDEVM_ATTR_DEV_BUS_NAME] || !tb[MLXDEVM_ATTR_DEV_NAME] ||
	    !tb[MLXDEVM_ATTR_PORT_INDEX])
		return MNL_CB_ERROR;

	pr_out_port(mlxdevm, tb);
	return MNL_CB_OK;
}

static int cmd_port_show(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
	int err;

	if (mlxdevm_argc(mlxdevm) == 0)
		flags |= NLM_F_DUMP;

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_PORT_GET, flags);

	if (mlxdevm_argc(mlxdevm) > 0) {
		err = mlxdevm_argv_parse_put(nlh, mlxdevm,
					     MLXDEVM_OPT_HANDLEP, 0);
		if (err)
			return err;
	}

	pr_out_section_start(mlxdevm, "port");
	err = mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, cmd_port_show_cb,
				     mlxdevm);
	pr_out_section_end(mlxdevm);
	return err;
}

static void cmd_port_function_help(void)
{
	pr_err("Usage: mlxdevm port function set DEV/PORT_INDEX [ hw_addr ADDR ] [ state STATE ] trust {on | off}\n");
	pr_err("       mlxdevm port function cap set DEV/PORT_INDEX [ roce TRUE/FALSE ] [ max_uc_macs VAL ]\n");

}

static int cmd_port_function_set(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err;

	if (mlxdevm_no_arg(mlxdevm)) {
		cmd_port_function_help();
		return 0;
	}
	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_PORT_SET,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm, MLXDEVM_OPT_HANDLEP,
				      MLXDEVM_OPT_PORT_FUNCTION_HW_ADDR |
				      MLXDEVM_OPT_PORT_FUNCTION_STATE |
				      MLXDEVM_OPT_PORT_FUNCTION_TRUST_STATE);
	if (err)
		return err;

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port_function_cap_set(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err;

	if (mlxdevm_no_arg(mlxdevm)) {
		cmd_port_function_help();
		return 0;
	}
	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_EXT_CAP_SET,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm, MLXDEVM_OPT_HANDLEP,
				     MLXDEVM_OPT_PORT_FN_CAP_ROCE |
				     MLXDEVM_OPT_PORT_FN_CAP_UC_LIST);
	if (err)
		return err;

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port_function_cap(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argv_match(mlxdevm, "help") ||
	    mlxdevm_no_arg(mlxdevm)) {
		cmd_port_function_help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "set")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_function_cap_set(mlxdevm);
	}
	pr_err("Command \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static int cmd_port_function(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argv_match(mlxdevm, "help") ||
	    mlxdevm_no_arg(mlxdevm)) {
		cmd_port_function_help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "set")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_function_set(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "cap")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_function_cap(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "rate")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_function_rate(mlxdevm);
	}
	pr_err("Command \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static void cmd_port_add_help(void)
{
	pr_err("       mlxdevm port add { DEV | DEV/PORT_INDEX } flavour FLAVOUR pfnum PFNUM [ sfnum SFNUM ] [ controller CNUM ]\n");
}

static int cmd_port_add(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err;

	if (mlxdevm_argv_match(mlxdevm, "help") ||
				mlxdevm_no_arg(mlxdevm)) {
		cmd_port_add_help();
		return 0;
	}

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_PORT_NEW,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm, MLXDEVM_OPT_HANDLE |
				     MLXDEVM_OPT_HANDLEP |
				     MLXDEVM_OPT_PORT_FLAVOUR |
				     MLXDEVM_OPT_PORT_PFNUMBER,
				     MLXDEVM_OPT_PORT_SFNUMBER |
				     MLXDEVM_OPT_PORT_CONTROLLER);
	if (err)
		return err;

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, cmd_port_show_cb,
				      mlxdevm);
}

static void cmd_port_del_help(void)
{
	pr_err("       mlxdevm port del DEV/PORT_INDEX\n");
}

static int cmd_port_del(struct mlxdevm *mlxdevm)
{
	struct nlmsghdr *nlh;
	int err;

	if (mlxdevm_argv_match(mlxdevm, "help") ||
	    mlxdevm_no_arg(mlxdevm)) {
		cmd_port_del_help();
		return 0;
	}

	nlh = mnlu_gen_socket_cmd_prepare(&mlxdevm->nlg,
					  MLXDEVM_CMD_PORT_DEL,
					  NLM_F_REQUEST | NLM_F_ACK);

	err = mlxdevm_argv_parse_put(nlh, mlxdevm, MLXDEVM_OPT_HANDLEP, 0);
	if (err)
		return err;

	return mnlu_gen_socket_sndrcv(&mlxdevm->nlg, nlh, NULL, NULL);
}

static int cmd_port(struct mlxdevm *mlxdevm)
{
	if (mlxdevm_argv_match(mlxdevm, "help")) {
		cmd_port_help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "show") ||
		   mlxdevm_argv_match(mlxdevm, "list") ||
		   mlxdevm_no_arg(mlxdevm)) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_show(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "function")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_function(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "add")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_add(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "del")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port_del(mlxdevm);
	}


	pr_err("Command \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static void help(void)
{
	pr_err("Usage: mlxdevm [ OPTIONS ] OBJECT { COMMAND | help }\n"
	       "       mlxdevm [ -f[orce] ] -b[atch] filename\n"
	       "where  OBJECT := { dev | port }\n"
	       "       OPTIONS := { -V[ersion] | -n[o-nice-names] | -j[son] | -p[retty] | -v[erbose] }\n");
}

static int mlxdevm_cmd(struct mlxdevm *mlxdevm, int argc, char **argv)
{
	mlxdevm->argc = argc;
	mlxdevm->argv = argv;

	if (mlxdevm_argv_match(mlxdevm, "help") ||
			mlxdevm_no_arg(mlxdevm)) {
		help();
		return 0;
	} else if (mlxdevm_argv_match(mlxdevm, "dev")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_dev(mlxdevm);
	} else if (mlxdevm_argv_match(mlxdevm, "port")) {
		mlxdevm_arg_inc(mlxdevm);
		return cmd_port(mlxdevm);
	}
	pr_err("Object \"%s\" not found\n", mlxdevm_argv(mlxdevm));
	return -ENOENT;
}

static int mlxdevm_init(struct mlxdevm *mlxdevm)
{
	int err;

	err = mnlu_gen_socket_open(&mlxdevm->nlg, MLXDEVM_GENL_NAME,
				   MLXDEVM_GENL_VERSION);
	if (err) {
		pr_err("Failed to connect to mlxdevm Netlink\n");
		return -errno;
	}

	err = ifname_map_init(mlxdevm);
	if (err) {
		pr_err("Failed to create index map\n");
		goto err_ifname_map_create;
	}
	new_json_obj_plain(mlxdevm->json_output);
	return 0;

err_ifname_map_create:
	mnlu_gen_socket_close(&mlxdevm->nlg);
	return err;
}

static void mlxdevm_fini(struct mlxdevm *mlxdevm)
{
	delete_json_obj_plain();
	ifname_map_fini(mlxdevm);
	mnlu_gen_socket_close(&mlxdevm->nlg);
}

static struct mlxdevm *mlxdevm_alloc(void)
{
	struct mlxdevm *mlxdevm;

	mlxdevm = calloc(1, sizeof(*mlxdevm));
	if (!mlxdevm)
		return NULL;
	return mlxdevm;
}

static void mlxdevm_free(struct mlxdevm *mlxdevm)
{
	free(mlxdevm);
}

static int mlxdevm_batch_cmd(int argc, char *argv[], void *data)
{
	struct mlxdevm *mlxdevm = data;

	return mlxdevm_cmd(mlxdevm, argc, argv);
}

static int mlxdevm_batch(struct mlxdevm *mlxdevm, const char *name,
			  bool force)
{
	return do_batch(name, force, mlxdevm_batch_cmd, mlxdevm);
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "Version",		no_argument,		NULL, 'V' },
		{ "force",		no_argument,		NULL, 'f' },
		{ "batch",		required_argument,	NULL, 'b' },
		{ "no-nice-names",	no_argument,		NULL, 'n' },
		{ "json",		no_argument,		NULL, 'j' },
		{ "pretty",		no_argument,		NULL, 'p' },
		{ "verbose",		no_argument,		NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	const char *batch_file = NULL;
	bool force = false;
	struct mlxdevm *mlxdevm;
	int opt;
	int err;
	int ret;

	mlxdevm = mlxdevm_alloc();
	if (!mlxdevm) {
		pr_err("Failed to allocate memory for mlxdevm\n");
		return EXIT_FAILURE;
	}

	while ((opt = getopt_long(argc, argv, "Vfb:njpv:",
				  long_options, NULL)) >= 0) {

		switch (opt) {
		case 'V':
			printf("mlxdevm utility, iproute2-%s\n", version);
			ret = EXIT_SUCCESS;
			goto mlxdevm_free;
		case 'f':
			force = true;
			break;
		case 'b':
			batch_file = optarg;
			break;
		case 'n':
			mlxdevm->no_nice_names = true;
			break;
		case 'j':
			mlxdevm->json_output = true;
			break;
		case 'p':
			pretty = true;
			break;
		case 'v':
			mlxdevm->verbose = true;
			break;
		default:
			pr_err("Unknown option.\n");
			help();
			ret = EXIT_FAILURE;
			goto mlxdevm_free;
		}
	}

	argc -= optind;
	argv += optind;

	err = mlxdevm_init(mlxdevm);
	if (err) {
		ret = EXIT_FAILURE;
		goto mlxdevm_free;
	}

	if (batch_file)
		err = mlxdevm_batch(mlxdevm, batch_file, force);
	else
		err = mlxdevm_cmd(mlxdevm, argc, argv);

	if (err) {
		ret = EXIT_FAILURE;
		goto mlxdevm_fini;
	}

	ret = EXIT_SUCCESS;

mlxdevm_fini:
	mlxdevm_fini(mlxdevm);
mlxdevm_free:
	mlxdevm_free(mlxdevm);

	return ret;
}
