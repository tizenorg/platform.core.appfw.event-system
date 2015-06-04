#include <stdio.h>
#include <glib.h>
#include <aul.h>
#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <Ecore.h>
#include <gio/gio.h>
#include <assert.h>
#include <package-manager.h>
#include <pkgmgr-info.h>
#include <appsvc/appsvc.h>
#include <eventsystem.h>
#include <bundle.h>

#undef LOG_TAG
#define LOG_TAG "ESD"

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

static GHashTable *event_launch_table; /* table of events for launch_on_event*/

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
const char *earlier_event_list[] = {
	SYS_EVENT_ESD_STATUS,
	SYS_EVENT_BATTERY_CHARGER_STATUS,
	SYS_EVENT_USB_STATUS,
	SYS_EVENT_LOW_MEMORY,
	SYS_EVENT_BOOT_COMPLETED,
	SYS_EVENT_SYSTEM_SHUTDOWN
};

static GHashTable *earlier_event_table; /* table of events for earlier_data */

typedef struct __earlier_table_item {
	char *event_name;
	guint reg_id;
	bundle *earlier_data; /* event-data from earlier occurrence */
} earlier_item;
#endif

typedef struct __eventlaunch_item_param {
	char *app_id;
} eventlaunch_item_param_s;

typedef struct esd_list_item {
	char *pkg_id;
	char *app_id;
} esd_list_item_s;

typedef struct  __event_launch_table_item {
	char *event_name;
	char *package_name; /* just for passing pointer to app-list removal func */
	GList *app_list_evtlaunch; /* app-list for on-event-launch */
	guint reg_id;
} event_launch_item;

enum __pkg_event_type {
	UNKNOWN = 0,
	INSTALL,
	UNINSTALL,
	UPDATE,
};

typedef struct __pkgmgr_event {
	int type;
	char *pkgid;
} esd_pkgmgr_event;

typedef struct __esd_event_param {
	char *event_name;
	bundle *event_data;
	void *user_data;
} esd_event_param;

typedef struct esd_info {
	pkgmgr_client *client;
} esd_info_s;
static esd_info_s s_info;


static int __esd_add_appinfo_handler(const pkgmgrinfo_appinfo_h handle, void *data);
static void __esd_event_handler(char *event_name, bundle *data, void *user_data);

static int __get_sender_pid(GDBusConnection *conn, const char *sender_name)
{
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int pid = 0;

	msg = g_dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "GetConnectionUnixProcessID");
	if (!msg) {
		_D("Can't allocate new method call");
		goto out;
	}

	g_dbus_message_set_body(msg, g_variant_new ("(s)", sender_name));
	reply = g_dbus_connection_send_message_with_reply_sync(conn, msg,
		G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_E("Failed to get pid [%s]", err->message);
			g_error_free(err);
		}
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	g_variant_get(body, "(u)", &pid);

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

  return pid;
}

void __esd_free_app_list(gpointer data)
{
	char *n = (char *)data;

	FREE_AND_NULL(n);
}

static void esd_print_appid_with_eventid(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	char *event_name = (char *)user_data;

	_D("event_name(%s)-app_id(%s)-pkg_id(%s)", event_name, item->app_id, item->pkg_id);
}

static void esd_print_interested_event(gpointer data, gpointer user_data)
{
	event_launch_item *el_item = (event_launch_item *)data;
	char *event_name = (char *)el_item->event_name;
	_D("event_name = (%s)", event_name);
	g_list_foreach(el_item->app_list_evtlaunch, esd_print_appid_with_eventid, event_name);
}

static void esd_launch_table_print_items(void)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, event_launch_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		esd_print_interested_event(value, NULL);
	}
}

static int esd_find_compare_by_list_item(gconstpointer data, gconstpointer user_data)
{
	esd_list_item_s *item_1 = (esd_list_item_s *)user_data;
	esd_list_item_s *item_2 = (esd_list_item_s *)data;

	return strcmp(item_1->app_id, item_2->app_id) |
		strcmp(item_1->pkg_id, item_2->pkg_id);
}

static int __esd_get_pkgid_by_appid(const char *app_id, char **pkg_id)
{
	pkgmgrinfo_appinfo_h handle = NULL;
	char *temp_val = NULL;
	int ret = 0;

	*pkg_id = NULL;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(app_id, getuid(), &handle);
	if (ret < 0) {
		_E("failed to get appinfo");
		ret = ES_R_ERROR;
		goto out;
	}

	ret = pkgmgrinfo_appinfo_get_pkgname(handle, &temp_val);
	if (ret == PMINFO_R_OK && temp_val) {
		*pkg_id = strdup(temp_val);
		_D("pkg_id(%s)", *pkg_id);
	} else {
		_E("failed to get pkgname");
		ret = pkgmgrinfo_appinfo_destroy_appinfo(handle);
		if (ret != PMINFO_R_OK) {
			_E("failed to destroy appinfo");
		}
		ret = ES_R_ERROR;
		goto out;
	}
	ret = pkgmgrinfo_appinfo_destroy_appinfo(handle);
	if (ret != PMINFO_R_OK) {
		_E("failed to destroy appinfo");
		free(*pkg_id);
		ret = ES_R_ERROR;
		goto out;
	}

	ret = ES_R_OK;

out:
	return ret;
}

static int __esd_add_list_item(event_launch_item *el_item,
		const char *app_id, const char *pkg_id)
{
	char *_pkgid = NULL;
	esd_list_item_s *item_of_list = NULL;

	if (pkg_id == NULL) {
		if (__esd_get_pkgid_by_appid(app_id, &_pkgid) < 0) {
			return ES_R_ERROR;
		}
	} else {
		_pkgid = (char *)pkg_id;
	}

	item_of_list = calloc(1, sizeof(esd_list_item_s));
	if (item_of_list == NULL) {
		_E("out_of_memory");
		free(_pkgid);
		return ES_R_ENOMEM;
	}
	item_of_list->app_id = (char *)app_id;
	item_of_list->pkg_id = _pkgid;
	el_item->app_list_evtlaunch =
		g_list_append(el_item->app_list_evtlaunch, item_of_list);

	return ES_R_OK;
}

static int __esd_add_launch_item(const char *event_name, const char *appid)
{
	GList *app_list = NULL;
	guint subscription_id = 0;
	char *app_id = NULL;
	char *pkg_id = NULL;
	esd_list_item_s *item_of_list = NULL;

	event_launch_item *el_item =
		(event_launch_item *)g_hash_table_lookup(event_launch_table, event_name);

	if (el_item) {
		if (__esd_get_pkgid_by_appid(appid, &pkg_id) < 0) {
			return ES_R_ERROR;
		}
		item_of_list = calloc(1, sizeof(esd_list_item_s));
		if (item_of_list == NULL) {
			_E("memory alloc failed");
			free(pkg_id);
			return ES_R_ENOMEM;
		}
		item_of_list->app_id = (char *)appid;
		item_of_list->pkg_id = pkg_id;

		app_list = g_list_find_custom(el_item->app_list_evtlaunch,
				item_of_list, (GCompareFunc)esd_find_compare_by_list_item);
		free(item_of_list);
		if (app_list == NULL) {
			_D("add new item (list item only)");
			app_id = strdup((char *)appid);
			if (!app_id) {
				_E("out_of_memory");
				free(pkg_id);
				return ES_R_ENOMEM;
			}
			if (__esd_add_list_item(el_item, app_id, pkg_id) < 0) {
				_E("failed to add list item");
				free(app_id);
				free(pkg_id);
				return ES_R_ERROR;
			}
		}
	} else {
		_D("add new item (all)");
		event_launch_item *eli = calloc(1, sizeof(event_launch_item));
		if (!eli) {
			_E("memory alloc failed");
			return ES_R_ENOMEM;
		}

		eli->event_name = strdup(event_name);
		if (!eli->event_name) {
			_E("out_of_memory");
			FREE_AND_NULL(eli);
			return ES_R_ENOMEM;
		}

		app_id = strdup((char *)appid);
		if (!app_id) {
			_E("out_of_memory");
			FREE_AND_NULL(eli->event_name);
			FREE_AND_NULL(eli);
			return ES_R_ENOMEM;
		}
		if (__esd_add_list_item(eli, app_id, NULL) < 0) {
			_E("failed to add list item");
			free(app_id);
			FREE_AND_NULL(eli->event_name);
			FREE_AND_NULL(eli);
			return ES_R_ERROR;
		}

		g_hash_table_insert(event_launch_table, eli->event_name, eli);

		eventsystem_register_event(eli->event_name, &subscription_id,
					(eventsystem_handler)__esd_event_handler, NULL);
		if (subscription_id == 0) {
			_E("signal subscription error, event_name(%s), app_id(%s)",
				eli->event_name, app_id);
			return ES_R_ERROR;
		} else {
			eli->reg_id = subscription_id;
		}
	}

	return ES_R_OK;
}

static void __esd_remove_app_list(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	event_launch_item *eli = (event_launch_item *)user_data;

	if (!strcmp(eli->package_name, item->pkg_id)) {
		_D("pkg_id(%s), app_id(%s)", eli->package_name, item->app_id);
		eli->app_list_evtlaunch =
			g_list_remove_all(eli->app_list_evtlaunch, data);
	}
}

static int esd_remove_launch_item(gpointer data, const char *pkg_id)
{
	event_launch_item *eli = (event_launch_item *)data;
	GList *first_list = NULL;

	eli->package_name = (char *)pkg_id;
	g_list_foreach(eli->app_list_evtlaunch, __esd_remove_app_list, eli);

	first_list = g_list_first(eli->app_list_evtlaunch);
	if (first_list == NULL) {
		if (eli->reg_id) {
			eventsystem_unregister_event(eli->reg_id);
		}
		return ES_R_REMOVE;
	}

	return ES_R_OK;
}

static int esd_launch_table_remove_items(const char *pkg_id)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, event_launch_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (esd_remove_launch_item(value, pkg_id) == ES_R_REMOVE) {
			_D("remove item itself");
			g_hash_table_iter_remove(&iter);
		}
	}

	return ES_R_OK;
}

static void esd_event_launch_with_appid(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	char *app_id = item->app_id;
	esd_event_param *eep = (esd_event_param *)user_data;
	static unsigned int req_id;
	int pid;

	_D("launch_on_event: app_id(%s), event_name(%s)", app_id, eep->event_name);

	if (!aul_app_is_running(app_id)) {
		char event_uri[1024] = {0, };
		snprintf(event_uri, 1024, "event://%s", eep->event_name);
		bundle *b = bundle_dup(eep->event_data);
		appsvc_set_operation(b, APPSVC_OPERATION_LAUNCH_ON_EVENT);
		appsvc_set_uri(b, event_uri);
		appsvc_set_appid(b, app_id);

		pid = appsvc_usr_run_service(b, req_id++, NULL, eep->user_data, getuid());
		_D("pid(%d)", pid);

		bundle_free(b);
	} else {
		_D("already is running");
	}
}

static void esd_check_event_launch_with_eventid(gpointer data, gpointer user_data)
{
	event_launch_item *el_item = (event_launch_item *)data;
	esd_event_param *eep = (esd_event_param *)user_data;

	if (strcmp(eep->event_name, (char *)el_item->event_name) == 0) {
		g_list_foreach(el_item->app_list_evtlaunch,
			esd_event_launch_with_appid, user_data);
	}
}

static void __esd_event_handler(char *event_name, bundle *data, void *user_data)
{
	_D("event_name(%s)", event_name);

	event_launch_item *el_item =
		(event_launch_item *)g_hash_table_lookup(event_launch_table, event_name);

	if (el_item == NULL) {
		return;
	}

	if (el_item->app_list_evtlaunch != NULL) {
		esd_event_param *eep = calloc(1, sizeof(esd_event_param));
		if (!eep) {
			_E("memory alloc failed");
			return;
		}
		eep->event_name = event_name;
		eep->event_data = data;
		eep->user_data = (void *)user_data;
		esd_check_event_launch_with_eventid(el_item, eep);
		free(eep);
	}
}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static void __esd_earlier_event_handler(char *event_name, bundle *data, void *user_data)
{
	_D("event_name(%s)", event_name);

	earlier_item *item =
		(earlier_item *)g_hash_table_lookup(earlier_event_table, event_name);

	/* update earlier value */
	if (item->earlier_data != NULL) {
		bundle_free(item->earlier_data);
	}
	item->earlier_data = bundle_dup(data);
}
#endif

static GDBusNodeInfo *introspection_data;
static const gchar introspection_xml[] =
"<node>"
"	<interface name='tizen.system.event.app2esd'>"
"		<method name='CheckUserCertValidation'>"
"			<arg type='i' name='frompid' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='CheckUserSendValidation'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='RequestEventLaunch'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='eventdata' direction='in'/>"
"			<arg type='i' name='datalen' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='RequestSendingEvent'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='eventdata' direction='in'/>"
"			<arg type='i' name='datalen' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
"		<method name='GetEarlierData'>"
"			<arg type='s' name='appid' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"			<arg type='i' name='len' direction='out'/>"
"			<arg type='s' name='earlier_data' direction='out'/>"
"		</method>"
#endif
"	</interface>"
"</node>";

static void handle_method_call(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *method_name,
		GVariant *parameters, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	GVariant *param = NULL;
	int result = 0;

	if (g_strcmp0(method_name, "CheckUserCertValidation") == 0) {
		char app_id[256] = {0, };
		char from_appid[256] = {0, };
		int from_pid = 0;
		int sender_pid = 0;
		int ret = 0;

		g_variant_get(parameters, "(i)", &from_pid);

		_D("from_pid(%d)", from_pid);

		if (from_pid > 0) {
			ret = aul_app_get_appid_bypid(from_pid, from_appid, sizeof(from_appid));
			if (ret != AUL_R_OK) {
				_E("failed to get appid by from_pid");
				result = ES_R_ERROR;
				goto out_1;
			}
		}

		sender_pid = __get_sender_pid(connection, sender);

		if (sender_pid > 0) {
			ret = aul_app_get_appid_bypid(sender_pid, app_id, sizeof(app_id));
			if (ret != AUL_R_OK) {
				_E("failed to get appid by sender_pid");
				result = ES_R_ERROR;
				goto out_1;
			}
		} else {
			_E("failed to get sender_pid");
			goto out_1;
		}

		pkgmgrinfo_cert_compare_result_type_e res;
		ret = pkgmgrinfo_pkginfo_compare_usr_app_cert_info(app_id, from_appid,
				getuid(), &res);
		if (ret < 0) {
			_E("CheckCertificate() Failed");
			result = ES_R_ERROR;
			goto out_1;
		}

		if (res != PMINFO_CERT_COMPARE_MATCH) {
			_E("CheckCertificate() Failed : ERROR_CERTIFICATE_NOT_MATCH");
			result = ES_R_EINVAL;
			goto out_1;
		}

		result = 1;
		param = g_variant_new("(i)", result);
out_1:
		_D("app_id(%s), from_appid(%s), result(%d)", app_id, from_appid, result);
		g_dbus_method_invocation_return_value(invocation, param);
	} else if (g_strcmp0(method_name, "CheckUserSendValidation") == 0) {
		char *event_name = NULL;
		char app_id[256] = {0, };
		char valid_name[1024];
		char *user_defined_name = NULL;
		int sender_pid = 0;
		int ret = 0;
		int len = 0;

		g_variant_get(parameters, "(s)", &event_name);

		_D("event_name(%s)", event_name);

		sender_pid = __get_sender_pid(connection, sender);

		if (sender_pid > 0) {
			ret = aul_app_get_appid_bypid(sender_pid, app_id, sizeof(app_id));
			if (ret != AUL_R_OK) {
				_E("failed to get appid by sender_pid");
				result = ES_R_ERROR;
				goto out_2;
			}
		} else {
			_E("failed to get sender_pid");
			goto out_2;
		}

		snprintf(valid_name, 1024, "%s%s.", USER_EVENT_NAME_PREFIX, app_id);
		len = strlen(valid_name);

		_D("valid_name(%s)", valid_name);

		if (strncmp(event_name, valid_name, len) != 0) {
			_E("appid misamatch");
			result = ES_R_EINVAL;
			goto out_2;
		} else {
			user_defined_name = strdup(&event_name[len]);
			len = strlen(user_defined_name);
			if (len < 1 || len > 127) {
				_E("Invalid Length of user-defined name");
				result = ES_R_EINVAL;
				goto out_2;
			}
			free(user_defined_name);
		}

		result = 1;
		param = g_variant_new("(i)", result);
out_2:
		_D("event_name(%s), result(%d)", event_name, result);
		g_dbus_method_invocation_return_value(invocation, param);
	} else if (g_strcmp0(method_name, "RequestEventLaunch") == 0) {
		char *event_name = NULL;
		bundle_raw *raw = NULL;
		bundle *b = NULL;
		int len = 0;

		g_variant_get(parameters, "(ssi)", &event_name, &raw, &len);

		b = bundle_decode(raw, len);
		__esd_event_handler(event_name, b, NULL);
		bundle_free(b);

		result = 1;
		param = g_variant_new("(i)", result);

		_D("event_name(%s), result(%d)", event_name, result);
		g_dbus_method_invocation_return_value(invocation, param);
	} else if (g_strcmp0(method_name, "RequestSendingEvent") == 0) {
		char *event_name = NULL;
		bundle_raw *raw = NULL;
		bundle *b = NULL;
		int len = 0;

		g_variant_get(parameters, "(ssi)", &event_name, &raw, &len);

		b = bundle_decode(raw, len);
		eventsystem_send_system_event(event_name, b);
		bundle_free(b);

		result = 1;
		param = g_variant_new("(i)", result);

		_D("event_name(%s), result(%d)", event_name, result);
		g_dbus_method_invocation_return_value(invocation, param);
#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	} else if (g_strcmp0(method_name, "GetEarlierData") == 0) {
		char *event_name = NULL;
		bundle *b = NULL;
		bundle_raw *raw = NULL;
		int len = 0;

		g_variant_get(parameters, "(s)", &event_name);

		if (event_name && strlen(event_name) > 0) {
			_D("event_name(%s)", event_name);
			result = ES_R_OK;
		} else {
			_E("invalid appid(%s)", event_name);
			result = ES_R_ERROR;
		}

		earlier_item *item =
			(earlier_item *)g_hash_table_lookup(earlier_event_table, event_name);

		if (item != NULL) {
			if (item->earlier_data) {
				b = bundle_dup(item->earlier_data);
				bundle_add_str(b, "is_earlier_data", "true");
				bundle_encode(b, &raw, &len);
				bundle_free(b);
			}
		}

		param = g_variant_new("(iis)", result, len, raw);

		_D("result(%d), len(%d)", result, len);
		g_dbus_method_invocation_return_value(invocation, param);

		bundle_free_encoded_rawdata(&raw);
#endif
	}
}

static const GDBusInterfaceVTable interface_vtable = {
	handle_method_call,
	NULL,
	NULL
};

static void on_bus_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_D("on_bus_acquired(%s)", name);

	guint reg_id = 0;
	GError *error = NULL;

	reg_id = g_dbus_connection_register_object(connection,
		ESD_OBJECT_PATH,
		introspection_data->interfaces[0],
		&interface_vtable,
		NULL, NULL, &error);
	if (reg_id == 0) {
		_E("g_dbus_connection_register_object error(%s)", error->message);
		g_error_free (error);
	}
}

static void on_name_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_D("on_name_acquired(%s)", name);

	bundle *b = bundle_create();
	bundle_add_str(b, EVT_KEY_ESD_STATUS, EVT_VAL_ESD_STARTED);
	eventsystem_send_system_event(SYS_EVENT_ESD_STATUS, b);
	bundle_free(b);
}

static void on_name_lost(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_D("on_name_lost(%s)", name);
}

static int __esd_before_loop(void)
{
	GList *es_info = NULL;
	GList *tmp_es_info = NULL;
	int ret = 0;

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	guint subscription_id = 0;
	int i, size;

	earlier_event_table = g_hash_table_new(g_str_hash, g_str_equal);

	_I("register events for earlier_data");
	size = sizeof(earlier_event_list)/sizeof(*earlier_event_list);
	for (i = 0; i < size; i++) {
		char *event_name = NULL;
		event_name = (char *)earlier_event_list[i];
		_I("event_name(%s)", event_name);

		earlier_item *item = calloc(1, sizeof(earlier_item));
		item->event_name = strdup(event_name);
		if (item->event_name == NULL) {
			_E("out of memory");
			return ES_R_ERROR;
		}
		g_hash_table_insert(earlier_event_table, event_name, item);

		eventsystem_register_event(item->event_name, &subscription_id,
					(eventsystem_handler)__esd_earlier_event_handler, NULL);
		if (subscription_id == 0) {
			_E("signal subscription error, event_name(%s)",	item->event_name);
			return ES_R_ERROR;
		} else {
			item->reg_id = subscription_id;
		}
	}
#endif

	event_launch_table = g_hash_table_new(g_str_hash, g_str_equal);

	_I("get event launch list");
	ret = pkgmgrinfo_appinfo_get_usr_installed_list(__esd_add_appinfo_handler, getuid(), NULL);
	if (ret < 0) {
		_E("pkgmgrinfo_appinfo_get_usr_installed_list error");
		return ES_R_ERROR;
	}
	esd_launch_table_print_items();
	/* gdbus setup for method call */
	GError *error = NULL;
	guint owner_id = 0;
	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	if (!introspection_data) {
		_E("g_dbus_node_info_new_for_xml error(%s)", error->message);
		g_error_free (error);
		return ES_R_ERROR;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
		ESD_BUS_NAME,
		G_BUS_NAME_OWNER_FLAGS_NONE,
		on_bus_acquired,
		on_name_acquired,
		on_name_lost,
		NULL, NULL);
	if (!owner_id) {
		_E("g_bus_own_name error");
		g_dbus_node_info_unref(introspection_data);
		return ES_R_ERROR;
	}

	return ES_R_OK;
}

static void esd_pkgmgr_event_free(esd_pkgmgr_event *pkg_event)
{
	pkg_event->type = UNKNOWN;
	if (pkg_event->pkgid) {
		free(pkg_event->pkgid);
		pkg_event->pkgid = NULL;
	}
}

#define OPERATION_LAUNCH_ON_EVENT "http://tizen.org/appcontrol/operation/launch_on_event"
static int __esd_appcontrol_cb(const char *operation, const char *uri, const char *mime, void *data)
{
	char *appid = (char *)data;

	if (!strcmp(operation, OPERATION_LAUNCH_ON_EVENT)) {
		if (__esd_add_launch_item(uri, appid)) {
			_E("failed to add item for %s", appid);
		}
	}

	return 0;
}

static int __esd_add_appinfo_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	char *appid = NULL;
	pkgmgrinfo_app_component component_type;
	int ret = 0;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("fail to get appinfo");
		return ES_R_ERROR;
	}

	_D("appid(%s)", appid);

	ret = pkgmgrinfo_appinfo_get_component(handle, &componenet_type);
	if (ret != PMINFO_R_OK) {
		_E("failed to get component type");
		return ES_R_ERROR;
	}

	if (component_type != PMINFO_SVC_APP) {
		_E("not service app");
		return ES_R_OK;
	}

	ret = pkgmgrinfo_appinfo_foreach_appcontrol(handle, __esd_appcontrol_cb, appid);
	if (ret < 0) {
		_E("failed to get appcontrol info");
		return ES_R_ERROR;
	}

	return ES_R_OK;
}

static int esd_pkgmgr_event_callback(int req_id, const char *pkg_type,
		const char *pkgid, const char *key, const char *val,
		const void *pmsg, void *data)
{
	esd_pkgmgr_event *pkg_event = (esd_pkgmgr_event *)data;
	pkgmgrinfo_pkginfo_h handle = NULL;
	int ret = 0;

	_D("req_id(%d), pkg_type(%s), pkgid(%s), key(%s), val(%s)",
		req_id, pkg_type, pkgid, key, val);

	if (strncmp(key, "start", strlen(key)) == 0) {
		if (strcmp(val, "install") == 0) {
			_D("install start");
			pkg_event->type = INSTALL;
		} else if (strcmp(val, "uninstall") == 0) {
			_D("unistall start");
			pkg_event->type = UNINSTALL;
		} else if (strcmp(val, "update") == 0) {
			_D("update start");
			pkg_event->type = UPDATE;
		} else {
			_D("val(%s) start", val);
			esd_pkgmgr_event_free(pkg_event);
		}
	} else if (strcmp(key, "end") == 0 && strcmp(val, "ok") == 0) {
		if (pkg_event->type == INSTALL || pkg_event->type == UPDATE) {
			_D("install end (ok)");
			ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, &handle, getuid());
			if (ret < 0) {
				_E("failed to get pkginfo");
				esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
			ret = pkgmgrinfo_appinfo_get_list(handle,
				PMINFO_ALL_APP, __esd_add_appinfo_handler, NULL);
			if (ret < 0) {
				_E("failed to get appinfo");
				esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
			ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			if (ret < 0) {
				_E("failed to destroy pkginfo");
				esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
		} else if (pkg_event->type == UNINSTALL) {
			_D("uninstall end (ok)");
			esd_launch_table_remove_items(pkgid);
			esd_launch_table_print_items();
		}
		esd_pkgmgr_event_free(pkg_event);
	} else if (strcmp(key, "end") == 0 && strcmp(val, "fail") == 0) {
		_E("pkg_event(%d) falied", pkg_event->type);
		esd_pkgmgr_event_free(pkg_event);
	} else {
		if (strcmp(key, "install_percent") != 0) {
			esd_pkgmgr_event_free(pkg_event);
		}
	}

	return 0;
}

static int __esd_init()
{
	int req_id = 0;
	int ret = 0;

	g_type_init();
	ecore_init();

	pkgmgr_client *client = pkgmgr_client_new(PC_LISTENING);
	if (client == NULL) {
		_E("set pkgmgr client failed");
		return ES_R_ERROR;
	}

	esd_pkgmgr_event *pkg_event = calloc(1, sizeof(esd_pkgmgr_event));
	if (pkg_event == NULL) {
		_E("memory alloc failed");
		ret = pkgmgr_client_free(client);
		if (ret != PKGMGR_R_OK) {
			_E("pkgmgr_client_free failed(%d)", ret);
		}
		return ES_R_ENOMEM;
	}

	req_id = pkgmgr_client_listen_status(client, esd_pkgmgr_event_callback, pkg_event);
	if (req_id < 0) {
		_E("pkgmgr client listen failed");
		ret = pkgmgr_client_free(client);
		if (ret != PKGMGR_R_OK) {
			_E("pkgmgr_client_free failed(%d)", ret);
		}
		return ES_R_ERROR;
	}

	s_info.client = client;

	_D("ESD init done\n");

	return 0;
}

static void esd_remove_app_list(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;

	free(item->app_id);
	free(item->pkg_id);
}

static void esd_finalize(void)
{
	gpointer key, value;
	int ret = 0;

	_D("esd finalize");

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	if (earlier_event_table) {
		GHashTableIter iter;

		g_hash_table_iter_init(&iter, earlier_event_table);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			earlier_item *item = (earlier_item *)value;
			if (item) {
				eventsystem_unregister_event(item->reg_id);
				free(item->event_name);
				bundle_free(item->earlier_data);
				free(item);
			} else {
				LOGE("item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(earlier_event_table);
	}
#endif

	if (event_launch_table) {
		GHashTableIter iter;

		g_hash_table_iter_init(&iter, event_launch_table);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			event_launch_item *el_item = (event_launch_item *)value;
			if (el_item) {
				eventsystem_unregister_event(el_item->reg_id);
				free(el_item->event_name);
				g_list_foreach(el_item->app_list_evtlaunch,
					esd_remove_app_list, NULL);
				g_list_free(el_item->app_list_evtlaunch);
				free(el_item);
			} else {
				LOGE("item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(event_launch_table);
	}

	if (introspection_data) {
		g_dbus_node_info_unref(introspection_data);
	}

	if (s_info.client) {
		ret = pkgmgr_client_free(s_info.client);
		if (ret != PKGMGR_R_OK) {
			_E("pkgmgr_client_free failed(%d)", ret);
		}
	}
}

int main(int argc, char *argv[])
{
	_D("event system daemon : main()\n");

	if (__esd_init() != 0) {
		_E("ESD Initialization failed!\n");
		assert(0);
		return ES_R_ERROR;
	}

	if (__esd_before_loop() < 0) {
		_E("ESD failed!\n");
		esd_finalize();
		assert(0);
		return ES_R_ERROR;
	}

	ecore_main_loop_begin();

	_E("shutdown");

	esd_finalize();

	ecore_shutdown();

	return 0;
}
