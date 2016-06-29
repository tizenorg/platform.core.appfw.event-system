#include <stdio.h>
#include <glib.h>
#include <aul.h>
#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <Ecore.h>
#include <gio/gio.h>
#include <package-manager.h>
#include <pkgmgr-info.h>
#include <appsvc/appsvc.h>
#include <eventsystem.h>
#include <bundle_internal.h>
#include <fcntl.h>
#include <vconf.h>
#include <tzplatform_config.h>
#include <systemd/sd-login.h>
#include <cynara-client.h>
#include <cynara-creds-gdbus.h>
#include <cynara-session.h>
#include <security-manager.h>
#include "eventsystem_daemon.h"

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define ROOT_USER 0

static GHashTable *event_launch_table; /* table of events for launch_on_event*/

static const char *event_launch_support_list[] = {
	SYS_EVENT_BATTERY_CHARGER_STATUS,
	SYS_EVENT_USB_STATUS,
	SYS_EVENT_EARJACK_STATUS,
	SYS_EVENT_INCOMMING_MSG,
	SYS_EVENT_OUTGOING_MSG
};

struct privilege_info {
	const char *event_name;
	const char *privilege_name;
};

static const struct privilege_info privilege_check_list[] = {
	{SYS_EVENT_DISPLAY_STATE, "http://tizen.org/privilege/display"},
	{SYS_EVENT_WIFI_STATE, "http://tizen.org/privilege/network.get"},
	{SYS_EVENT_INCOMMING_MSG, "http://tizen.org/privilege/message.read"},
	{SYS_EVENT_OUTGOING_MSG, "http://tizen.org/privilege/message.read"}
};

static int privilege_check_size = sizeof(privilege_check_list)/sizeof(struct privilege_info);

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static const char *earlier_event_list[] = {
	SYS_EVENT_ESD_STATUS,
	SYS_EVENT_LOW_MEMORY,
	SYS_EVENT_BOOT_COMPLETED,
	SYS_EVENT_SYSTEM_SHUTDOWN,
	SYS_EVENT_BATTERY_CHARGER_STATUS
};

static GHashTable *earlier_event_table; /* table of events for earlier_data */

typedef struct __earlier_table_item {
	char *event_name;
	guint reg_id;
	bundle *earlier_data; /* event-data from earlier occurrence */
} earlier_item;

static bool g_is_bootcompleted = false;
#endif

static GHashTable *user_last_event_table; /* table of user events for last data */

struct __last_event_item {
	char *event_name;
	char *own_name;
};

static GHashTable *trusted_busname_table; /* table of dbus bus-names for trusted user-event */

typedef struct __trusted_busname_item {
	char *app_id;
	char *bus_name;
	int pid;
	uid_t uid;
} trusted_item;

typedef struct __eventlaunch_item_param {
	char *app_id;
} eventlaunch_item_param_s;

typedef struct esd_list_item {
	char *pkg_id;
	char *app_id;
	uid_t uid;
} esd_list_item_s;

typedef struct  __event_launch_table_item {
	char *event_name;
	char *package_name; /* just for passing pointer to app-list removal func */
	GList *app_list_evtlaunch; /* app-list for on-event-launch */
	guint reg_id;
	uid_t uid;
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

static Ecore_Fd_Handler *g_fd_handler;
sd_login_monitor *g_sd_monitor;

typedef struct __esd_appctrl_cb_data {
	char *appid;
	char *pkgid;
	uid_t uid;
} esd_appctrl_cb_data;

static void __esd_event_handler(char *event_name, bundle *data, void *user_data);
static int __esd_add_appinfo_handler(const pkgmgrinfo_appinfo_h handle, void *data);

static cynara *r_cynara = NULL;

static int __esd_init_cynara(void)
{
	int ret;

	ret  = cynara_initialize(&r_cynara, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		_E("cynara initialize failed.");
		return ret;
	}

	return 0;
}

static void __esd_finish_cynara(void)
{
	if (r_cynara)
		cynara_finish(r_cynara);
	r_cynara = NULL;
}

static void free_saved_event(struct __last_event_item *item)
{
	if (!item)
		return;

	free(item->event_name);
	free(item->own_name);
	free(item);
}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static int __esd_check_earlier_support(const char *event_name)
{
	int i = 0;
	int size = sizeof(earlier_event_list)/sizeof(*earlier_event_list);

	for (i = 0; i < size; i++) {
		if (strcmp(earlier_event_list[i], event_name) == 0)
			return true;
	}

	return false;
}
#endif

static int __esd_check_event_launch_support(const char *event_name)
{
	int i = 0;
	int size = sizeof(event_launch_support_list)/sizeof(*event_launch_support_list);

	for (i = 0; i < size; i++) {
		if (strcmp(event_launch_support_list[i], event_name) == 0)
			return true;
	}

	return false;
}

static int __get_sender_unixinfo(GDBusConnection *conn, const char *sender_name, const char *type)
{
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int ret = -1;
	unsigned int value;

	msg = g_dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", type);
	if (!msg) {
		_E("Can't allocate new method call");
		goto out;
	}

	g_dbus_message_set_body(msg, g_variant_new("(s)", sender_name));
	reply = g_dbus_connection_send_message_with_reply_sync(conn, msg,
		G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_E("Failed to get info [%s]", err->message);
			g_error_free(err);
		}
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	g_variant_get(body, "(u)", &value);
	ret = (int)value;

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return ret;
}

static int __get_sender_pid(GDBusConnection *conn, const char *sender_name)
{
	int pid = 0;

	pid = __get_sender_unixinfo(conn, sender_name, "GetConnectionUnixProcessID");
	if (pid < 0) {
		_E("failed to get pid");
		pid = 0;
	}

	_D("sender_name(%s), pid(%d)", sender_name, pid);

	return pid;
}

static int __get_sender_uid(GDBusConnection *conn, const char *sender_name)
{
	int uid = -1;

	uid = __get_sender_unixinfo(conn, sender_name, "GetConnectionUnixUser");
	if (uid < 0) {
		_E("failed to get uid");
	}

	_D("sender_name(%s), uid(%d)", sender_name, uid);

	return uid;
}

static int __esd_check_certificate_match(uid_t uid, const char *app_id, uid_t from_uid, const char *from_appid)
{
	pkgmgrinfo_cert_compare_result_type_e res;
	int ret = 0;

	_D("uid(%d), app_id(%s), from_uid(%d), from_appid(%s)", uid, app_id, from_uid, from_appid);

	ret = pkgmgrinfo_pkginfo_compare_usr_app_cert_info(app_id, from_appid, from_uid, &res);
	if (ret < 0) {
		_E("failed to check certificate");
		return ES_R_ERROR;
	}

	if (res != PMINFO_CERT_COMPARE_MATCH) {
		_D("certificat not match (%s)", app_id);
		return ES_R_EINVAL;
	}

	return ES_R_OK;
}

static bool __esd_check_application_validation(uid_t uid, const char *appid)
{
	int ret = 0;
	pkgmgrinfo_appinfo_h handle;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &handle);
	if (ret != PMINFO_R_OK)
		return false;

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	if (!aul_app_is_running_for_uid(appid, uid))
		return false;

	return true;
}

static void __esd_trusted_busname_print_items(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	g_hash_table_iter_init(&iter, trusted_busname_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		trusted_item *item = (trusted_item *)value;
		if (item)
			_D("uid(%d), appid(%s), pid(%d), busname(%s)", item->uid, item->app_id, item->pid, item->bus_name);
	}
}

static int __esd_trusted_busname_add_item(uid_t uid, const char *appid, const char *busname, int pid)
{
	char *app_id = NULL;
	char *bus_name = NULL;
	trusted_item *item = NULL;
	trusted_item *new_item;

	app_id = strdup(appid);
	if (app_id == NULL) {
		_E("out of memory");
		return ES_R_ENOMEM;
	}

	bus_name = strdup(busname);
	if (bus_name == NULL) {
		_E("out of memory");
		FREE_AND_NULL(app_id);
		return ES_R_ENOMEM;
	}

	item = (trusted_item *)g_hash_table_lookup(trusted_busname_table, app_id);

	if (item && item->bus_name && strcmp(item->bus_name, bus_name) == 0 &&
		(item->uid == uid)) {
		_D("already exist (%s, %s)", app_id, bus_name);
		FREE_AND_NULL(app_id);
		FREE_AND_NULL(bus_name);
	} else {
		new_item = calloc(1, sizeof(trusted_item));
		if (new_item == NULL) {
			_E("memory alloc failed");
			FREE_AND_NULL(app_id);
			FREE_AND_NULL(bus_name);
			return ES_R_ENOMEM;
		}
		new_item->uid = uid;
		new_item->app_id = app_id;
		new_item->bus_name = bus_name;
		new_item->pid = pid;
		g_hash_table_insert(trusted_busname_table, new_item->app_id, new_item);
		_D("added busname(%s)", new_item->bus_name);
	}

	return ES_R_OK;
}

static int __esd_check_trusted_events(GDBusConnection *conn, const char *list_name)
{
	GVariant *result;
	GError *error = NULL;
	GVariantIter *iter;
	gchar *str;
	char tmp_appid[128] = {0, };
	int pid = 0;
	int uid = 0;
	int ret = 0;

	result = g_dbus_connection_call_sync(conn,
		"org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		list_name, NULL, G_VARIANT_TYPE("(as)"), G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, &error);

	if (result == NULL) {
		_E("get (%s) error(%s)", list_name, error->message);
		g_error_free(error);
		return ES_R_ERROR;
	}

	g_variant_get(result, "(as)", &iter);
	while (g_variant_iter_loop(iter, "s", &str)) {
		if (!strstr((const char *)str, "event.busname.session"))
			continue;

		_D("list(%s), name(%s)", list_name, str);
		pid = __get_sender_pid(conn, (const char *)str);
		if (pid <= 0) {
			_E("failed to get pid(%d)", pid);
			continue;
		}

		uid = __get_sender_uid(conn, (const char *)str);
		if (uid < 0) {
			_E("failed to get uid(%d)", uid);
			continue;
		}
		_D("uid(%d)", uid);

		memset(tmp_appid, 0, sizeof(tmp_appid));
		ret = aul_app_get_appid_bypid_for_uid(pid, tmp_appid, sizeof(tmp_appid), (uid_t)uid);
		if (ret != AUL_R_OK) {
			_E("failed to get appid by pid(%d)", pid);
			continue;
		}

		_D("appid(%s)", tmp_appid);
		if (__esd_check_application_validation((uid_t)uid, tmp_appid)) {
			_D("add to table");
			ret = __esd_trusted_busname_add_item((uid_t)uid, tmp_appid, (const char *)str, pid);
			if (ret < 0)
				_E("failed to add item");
		}
	}
	g_variant_iter_free(iter);
	g_variant_unref(result);

	return ES_R_OK;
}

static int __esd_check_privilege_name(const char *event_name, char **privilege_name)
{
	int i = 0;

	*privilege_name = NULL;

	for (i = 0; i < privilege_check_size; i++) {
		if (strcmp(event_name, privilege_check_list[i].event_name) == 0) {
			*privilege_name = (char *)privilege_check_list[i].privilege_name;
			_D("[%d] privilege_name(%s)", i, *privilege_name);
			break;
		}
	}

	return ES_R_OK;
}

static bool __esd_check_valid_privilege_by_cynara(const char *appid, const char *client,
	const char *session, const char *user, const char *privilege_name)
{
	int ret = 0;
	bool has_privilege = false;

	_D("check privilege, (%s, %s, %s, %s, %s)", appid, client, session, user, privilege_name);

	ret = cynara_check(r_cynara, client, session, user, privilege_name);
	if (ret == CYNARA_API_ACCESS_ALLOWED) {
		_D("valid privilege");
		has_privilege = true;
	} else if (ret == CYNARA_API_ACCESS_DENIED) {
		_E("invalid privilege");
	} else {
		_E("failed to check privilege, error(%d)", ret);
	}

	return has_privilege;
}

static int __esd_check_app_privileged_event(uid_t uid, const char *appid, const char *pkgid, const char *event_name)
{
	char *privilege_name = NULL;
	int ret = 0;
	int result = 0;

	_D("event_name(%s), uid(%d), appid(%s), pkgid(%s)", event_name, uid, appid, pkgid);

	__esd_check_privilege_name(event_name, &privilege_name);

	if (privilege_name) {
		ret = security_manager_app_has_privilege(appid, privilege_name, uid, &result);
		if (ret != SECURITY_MANAGER_SUCCESS)
			_E("failed to check privilege(%d)", ret);
		_D("result(%d)", result);
	} else {
		result = 1;
	}

	return result;
}

static void __esd_print_appid_with_eventid(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	char *event_name = (char *)user_data;

	_D("event_name(%s)-uid(%d)-app_id(%s)-pkg_id(%s)", event_name, item->uid, item->app_id, item->pkg_id);
}

static void __esd_print_interested_event(gpointer data, gpointer user_data)
{
	event_launch_item *el_item = (event_launch_item *)data;
	char *event_name = (char *)el_item->event_name;
	_D("event_name = (%s)", event_name);
	g_list_foreach(el_item->app_list_evtlaunch, __esd_print_appid_with_eventid, event_name);
}

static void __esd_launch_table_print_items(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	g_hash_table_iter_init(&iter, event_launch_table);

	while (g_hash_table_iter_next(&iter, &key, &value))
		__esd_print_interested_event(value, NULL);
}

static int __esd_find_compare_by_list_item(gconstpointer data, gconstpointer user_data)
{
	esd_list_item_s *item_1 = (esd_list_item_s *)user_data;
	esd_list_item_s *item_2 = (esd_list_item_s *)data;

	return (item_1->uid != item_2->uid) |
		strcmp(item_1->app_id, item_2->app_id) |
		strcmp(item_1->pkg_id, item_2->pkg_id);
}

static int __esd_add_list_item(uid_t uid, event_launch_item *el_item,
		const char *app_id, const char *pkg_id)
{
	esd_list_item_s *item_of_list = NULL;

	item_of_list = calloc(1, sizeof(esd_list_item_s));
	if (item_of_list == NULL) {
		_E("out_of_memory");
		return ES_R_ENOMEM;
	}
	item_of_list->uid = uid;
	item_of_list->app_id = (char *)app_id;
	item_of_list->pkg_id = (char *)pkg_id;
	el_item->app_list_evtlaunch =
		g_list_append(el_item->app_list_evtlaunch, item_of_list);

	return ES_R_OK;
}

static int __esd_add_launch_item(uid_t uid, const char *event_name, const char *appid, const char *pkgid)
{
	GList *app_list = NULL;
	guint subscription_id = 0;
	char *app_id = NULL;
	char *pkg_id = NULL;
	esd_list_item_s *item_of_list = NULL;
	event_launch_item *eli;
	event_launch_item *el_item =
		(event_launch_item *)g_hash_table_lookup(event_launch_table, event_name);

	if (el_item) {
		item_of_list = calloc(1, sizeof(esd_list_item_s));
		if (item_of_list == NULL) {
			_E("memory alloc failed");
			return ES_R_ENOMEM;
		}
		item_of_list->uid = uid;
		item_of_list->app_id = (char *)appid;
		item_of_list->pkg_id = (char *)pkgid;

		app_list = g_list_find_custom(el_item->app_list_evtlaunch,
			item_of_list, (GCompareFunc)__esd_find_compare_by_list_item);
		free(item_of_list);
		if (app_list == NULL) {
			_D("add new item (list item only)");
			app_id = strdup((char *)appid);
			if (!app_id) {
				_E("out_of_memory");
				return ES_R_ENOMEM;
			}
			pkg_id = strdup((char *)pkgid);
			if (!pkg_id) {
				_E("out_of_memory");
				FREE_AND_NULL(app_id);
				return ES_R_ENOMEM;
			}
			if (__esd_add_list_item(uid, el_item, app_id, pkg_id) < 0) {
				_E("failed to add list item");
				FREE_AND_NULL(app_id);
				FREE_AND_NULL(pkg_id);
				return ES_R_ERROR;
			}
		}
	} else {
		_D("add new item (all)");
		eli = calloc(1, sizeof(event_launch_item));
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

		pkg_id = strdup((char *)pkgid);
		if (!pkg_id) {
			_E("out_of_memory");
			FREE_AND_NULL(app_id);
			FREE_AND_NULL(eli->event_name);
			FREE_AND_NULL(eli);
			return ES_R_ENOMEM;
		}

		if (__esd_add_list_item(uid, eli, app_id, pkg_id) < 0) {
			_E("failed to add list item");
			FREE_AND_NULL(app_id);
			FREE_AND_NULL(pkg_id);
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

static void __esd_remove_all_private_usr_app_list(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	event_launch_item *eli = (event_launch_item *)user_data;

	if (item->uid != GLOBAL_USER && !strcmp(eli->package_name, item->pkg_id)) {
		_D("uid(%d), app_id(%s), pkg_id(%s)", item->uid, item->app_id, eli->package_name);
		eli->app_list_evtlaunch = g_list_remove_all(eli->app_list_evtlaunch, data);
	}
}

static int __esd_launch_table_remove_private_usr_items(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	event_launch_item *eli = NULL;
	GList *first_list = NULL;

	g_hash_table_iter_init(&iter, event_launch_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		eli = (event_launch_item *)value;
		g_list_foreach(eli->app_list_evtlaunch, __esd_remove_all_private_usr_app_list, eli);

		first_list = g_list_first(eli->app_list_evtlaunch);
		if (first_list == NULL) {
			if (eli->reg_id)
				eventsystem_unregister_event(eli->reg_id);

			g_hash_table_iter_remove(&iter);
		}
	}

	return ES_R_OK;
}

static void __esd_remove_app_list(gpointer data, gpointer user_data)
{
	bool skip = false;
	esd_list_item_s *item = (esd_list_item_s *)data;
	event_launch_item *eli = (event_launch_item *)user_data;

	if (eli->uid != GLOBAL_USER && eli->uid != item->uid)
		skip = true;

	if (!skip && !strcmp(eli->package_name, item->pkg_id)) {
		_D("pkg_id(%s), app_id(%s)", eli->package_name, item->app_id);
		eli->app_list_evtlaunch =
			g_list_remove_all(eli->app_list_evtlaunch, data);
	}
}

static int __esd_remove_launch_item(uid_t uid, gpointer data, const char *pkg_id)
{
	event_launch_item *eli = (event_launch_item *)data;
	GList *first_list = NULL;

	eli->uid = uid;
	eli->package_name = (char *)pkg_id;
	g_list_foreach(eli->app_list_evtlaunch, __esd_remove_app_list, eli);

	first_list = g_list_first(eli->app_list_evtlaunch);
	if (first_list == NULL) {
		if (eli->reg_id)
			eventsystem_unregister_event(eli->reg_id);

		return ES_R_REMOVE;
	}

	return ES_R_OK;
}

static int __esd_launch_table_remove_items(uid_t uid, const char *pkg_id)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	g_hash_table_iter_init(&iter, event_launch_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (__esd_remove_launch_item(uid, value, pkg_id) == ES_R_REMOVE) {
			_D("remove item itself");
			g_hash_table_iter_remove(&iter);
		}
	}

	return ES_R_OK;
}

static void __esd_event_launch_with_appid(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;
	uid_t uid = item->uid;
	char *app_id = item->app_id;
	esd_event_param *eep = (esd_event_param *)user_data;
	static unsigned int req_id;
	int pid;
	char event_uri[1024];
	bundle *b;

	_D("launch_on_event: app_id(%s), event_name(%s), uid(%d)",
			app_id, eep->event_name, uid);

	if (!aul_app_is_running_for_uid(app_id, uid)) {
		snprintf(event_uri, sizeof(event_uri), "event://%s", eep->event_name);
		b = bundle_dup(eep->event_data);
		appsvc_set_operation(b, APPSVC_OPERATION_LAUNCH_ON_EVENT);
		appsvc_set_uri(b, event_uri);
		appsvc_set_appid(b, app_id);

		pid = appsvc_usr_run_service(b, req_id++, NULL, eep->user_data, uid);
		_D("uid(%d), pid(%d)", uid, pid);

		bundle_free(b);
	} else {
		_D("already is running or launch failed");
	}
}

static void __esd_check_event_launch_with_eventid(gpointer data, gpointer user_data)
{
	event_launch_item *el_item = (event_launch_item *)data;
	esd_event_param *eep = (esd_event_param *)user_data;

	if (strcmp(eep->event_name, (char *)el_item->event_name) == 0) {
		g_list_foreach(el_item->app_list_evtlaunch,
			__esd_event_launch_with_appid, user_data);
	}
}

static void __esd_launch_event_handler(char *event_name, bundle *data, void *user_data)
{
	const char *val;
	const char *msg_type;
	const char *msg_id;
	esd_event_param *eep;
	event_launch_item *el_item;

	_D("event_name(%s)", event_name);

	el_item = (event_launch_item *)g_hash_table_lookup(event_launch_table, event_name);
	if (el_item == NULL)
		return;

	if (el_item->app_list_evtlaunch != NULL) {
		if (strcmp(SYS_EVENT_BATTERY_CHARGER_STATUS, event_name) == 0) {
			val = bundle_get_val(data, EVT_KEY_BATTERY_CHARGER_STATUS);
			_D("charger val(%s)", val);
			if (val && (strcmp(EVT_VAL_BATTERY_CHARGER_CONNECTED, val) != 0))
				return;
		} else if (strcmp(SYS_EVENT_USB_STATUS, event_name) == 0) {
			val = bundle_get_val(data, EVT_KEY_USB_STATUS);
			_D("usb val(%s)", val);
			if (val && (strcmp(EVT_VAL_USB_CONNECTED, val) != 0))
				return;
		} else if (strcmp(SYS_EVENT_EARJACK_STATUS, event_name) == 0) {
			val = bundle_get_val(data, EVT_KEY_EARJACK_STATUS);
			_D("earjack val(%s)", val);
			if (val && (strcmp(EVT_VAL_EARJACK_CONNECTED, val) != 0))
				return;
		} else if (strcmp(SYS_EVENT_INCOMMING_MSG, event_name) == 0) {
			msg_type = bundle_get_val(data, EVT_KEY_MSG_TYPE);
			_D("msg_type(%s)", msg_type);
			if (msg_type == NULL)
				return;

			msg_id = bundle_get_val(data, EVT_KEY_MSG_ID);
			_D("msg_id(%s)", msg_id);
			if (msg_id == NULL)
				return;
		}

		eep = calloc(1, sizeof(esd_event_param));
		if (!eep) {
			_E("memory alloc failed");
			return;
		}
		eep->event_name = event_name;
		eep->event_data = data;
		eep->user_data = (void *)user_data;
		__esd_check_event_launch_with_eventid(el_item, eep);
		free(eep);
	}
}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static void __esd_print_earlier_event(gpointer data, gpointer user_data)
{
	earlier_item *item = (earlier_item *)data;
	char *event_name = (char *)item->event_name;
	const char *val;

	_D("event_name = (%s)", event_name);

	if (strcmp(event_name, SYS_EVENT_BOOT_COMPLETED) == 0) {
		if (item->earlier_data) {
			val = bundle_get_val(item->earlier_data, EVT_KEY_BOOT_COMPLETED);
			_D("boot_completed(%s)", val);
		}
	} else if (strcmp(event_name, SYS_EVENT_SYSTEM_SHUTDOWN) == 0) {
		if (item->earlier_data) {
			val = bundle_get_val(item->earlier_data, EVT_KEY_SYSTEM_SHUTDOWN);
			_D("shutdown(%s)", val);
		}
	} else if (strcmp(event_name, SYS_EVENT_LOW_MEMORY) == 0) {
		if (item->earlier_data) {
			val = bundle_get_val(item->earlier_data, EVT_KEY_LOW_MEMORY);
			_D("low_memory(%s)", val);
		}
	} else if (strcmp(event_name, SYS_EVENT_BATTERY_CHARGER_STATUS) == 0) {
		if (item->earlier_data) {
			val = bundle_get_val(item->earlier_data, EVT_KEY_BATTERY_CHARGER_STATUS);
			_D("charger_status(%s)", val);
		}
	}
}

static void __esd_earlier_table_print_items(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	g_hash_table_iter_init(&iter, earlier_event_table);

	while (g_hash_table_iter_next(&iter, &key, &value))
		__esd_print_earlier_event(value, NULL);
}

static void __esd_earlier_event_handler(char *event_name, bundle *data, void *user_data)
{
	int handle;
	earlier_item *item;
	_D("event_name(%s)", event_name);

	item = (earlier_item *)g_hash_table_lookup(earlier_event_table, event_name);
	if (item) {
		/* update earlier value */
		if (item->earlier_data != NULL)
			bundle_free(item->earlier_data);

		item->earlier_data = bundle_dup(data);

		if (!g_is_bootcompleted) {
			if (strcmp(event_name, SYS_EVENT_BOOT_COMPLETED) == 0) {
				handle = creat(ESD_BOOT_COMPLETED, 0640);
				if (handle != -1)
					close(handle);
				g_is_bootcompleted = true;
			}
		}
	}
}
#endif

static void __esd_event_handler(char *event_name, bundle *data, void *user_data)
{
	_D("event_name(%s)", event_name);

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	if (__esd_check_earlier_support(event_name))
		__esd_earlier_event_handler(event_name, data, user_data);
#endif

	if (__esd_check_event_launch_support(event_name))
		__esd_launch_event_handler(event_name, data, user_data);
}

static void __esd_trusted_busname_remove_item(char *bus_name)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	trusted_item *item;

	g_hash_table_iter_init(&iter, trusted_busname_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		item = (trusted_item *)value;
		if (item) {
			if (strcmp(bus_name, item->bus_name) == 0) {
				_D("remove trusted busname item(%s, %s)", item->app_id, item->bus_name);
				FREE_AND_NULL(item->app_id);
				FREE_AND_NULL(item->bus_name);
				FREE_AND_NULL(item);
				g_hash_table_iter_remove(&iter);

				__esd_trusted_busname_print_items();
			}
		}
	}
}

static void __esd_filter_name_owner_changed(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	char *name = NULL;
	char *old_owner = NULL;
	char *new_owner = NULL;
	int old_len = 0;
	int new_len = 0;

	g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);

	if (strstr(name, "event.busname.session")) {
		old_len = strlen(old_owner);
		new_len = strlen(new_owner);

		_D("changed name(%s), old_onwer(%s)(%d) -> new_onwer(%s)(%d)",
			name, old_owner, old_len, new_owner, new_len);

		if (old_len > 0 && new_len == 0)
			__esd_trusted_busname_remove_item(name);
		else if (old_len == 0 && new_len > 0)
			_D("new name owned");
		else
			_E("not-expected name change");
	}
}

static int __esd_dbus_name_monitor(GDBusConnection *connection)
{
	guint name_owner_changed_id = 0;

	name_owner_changed_id = g_dbus_connection_signal_subscribe(connection,
		"org.freedesktop.DBus", "org.freedesktop.DBus",
		"NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE,
		__esd_filter_name_owner_changed, NULL, NULL);

	_I("name_owner_changed_id(%d)", name_owner_changed_id);

	return ES_R_OK;
}

static int __esd_get_user_items(void)
{
	int ret = 0;
	int i = 0;
	uid_t *uids = NULL;
	uid_t cur_uid = 0;
	pkgmgrinfo_appinfo_filter_h handle = NULL;

	ret = sd_get_uids(&uids);
	if (ret < 0) {
		_E("failed to get uids (%d)", ret);
		return ES_R_ERROR;
	}

	if (ret == 0 || uids == NULL) {
		_I("there is no uid for now");
	} else {
		/* reset user's item */
		__esd_launch_table_remove_private_usr_items();
		for (i = 0; i < ret; i++) {
			cur_uid = uids[i];
			_I("found uid(%d)", cur_uid);

			ret = pkgmgrinfo_appinfo_filter_create(&handle);
			if (ret < 0) {
				_E("failed to create appinfo filter");
				return ES_R_ERROR;
			}
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
					PMINFO_APPINFO_PROP_APP_COMPONENT, "svcapp");
			if (ret < 0) {
				_E("failed to add appinfo filter string");
				return ES_R_ERROR;
			}
			ret = pkgmgrinfo_appinfo_filter_add_string(handle,
					PMINFO_APPINFO_PROP_APP_OPERATION, APPSVC_OPERATION_LAUNCH_ON_EVENT);
			if (ret < 0) {
				_E("failed to add appinfo filter string");
				return ES_R_ERROR;
			}
			ret = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle,
					__esd_add_appinfo_handler, &cur_uid, cur_uid);
			if (ret < 0) {
				_E("appinfo filter foreach error");
				return ES_R_ERROR;
			}
			pkgmgrinfo_appinfo_filter_destroy(handle);
		}
	}

	__esd_launch_table_print_items();

	return ES_R_OK;
}

static Eina_Bool __esd_fd_handler_func(void *data, Ecore_Fd_Handler *fd_handler)
{
	if (ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_READ)) {
		_I("fd read");
		__esd_get_user_items();
	}

	return ECORE_CALLBACK_CANCEL;
}

static int __esd_start_sd_monitor(void)
{
	int ret = 0;
	int fd = 0;

	ret = __esd_get_user_items();
	if (ret < 0)
		return ES_R_ERROR;

	ret = sd_login_monitor_new("uid", &g_sd_monitor);
	if (ret < 0) {
		_E("sd_login_monitor_new error (%d)", ret);
		return ES_R_ERROR;
	}

	fd = sd_login_monitor_get_fd(g_sd_monitor);
	if (fd < 0) {
		_E("sd_login_monitor_get_fd error");
		sd_login_monitor_unref(g_sd_monitor);
		return ES_R_ERROR;
	}

	g_fd_handler = ecore_main_fd_handler_add(fd,
		(Ecore_Fd_Handler_Flags)(ECORE_FD_READ | ECORE_FD_ERROR),
		__esd_fd_handler_func, NULL, NULL, NULL);
	if (g_fd_handler == NULL) {
		_E("fd_handler is NULL");
		sd_login_monitor_unref(g_sd_monitor);
		return ES_R_ERROR;
	}

	_I("setup sd-monitor done");

	return ES_R_OK;
}

static int __esd_stop_sd_monitor(void)
{
	_I("stop sd_monitor");
	if (g_fd_handler) {
		ecore_main_fd_handler_del(g_fd_handler);
		g_fd_handler = NULL;
	}

	sd_login_monitor_unref(g_sd_monitor);
	g_sd_monitor = 0;

	return ES_R_OK;
}

static GDBusNodeInfo *introspection_data;
static const gchar introspection_xml[] =
"<node>"
"	<interface name='tizen.system.event.app2esd'>"
"		<method name='CheckSenderValidation'>"
"			<arg type='i' name='senderpid' direction='in'/>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"			<arg type='s' name='senderid' direction='out'/>"
"		</method>"
"		<method name='GetTrustedPeerList'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"			<arg type='as' name='dest_list' direction='out'/>"
"		</method>"
"		<method name='SetupTrustedPeer'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='destination' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='CheckPrivilegeValidation'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='CheckUserSendValidation'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='RequestTrustedEventLaunch'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='eventdata' direction='in'/>"
"			<arg type='i' name='datalen' direction='in'/>"
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
"		<method name='KeepLastData'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='own_name' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"		<method name='CheckLastData'>"
"			<arg type='s' name='eventname' direction='in'/>"
"			<arg type='s' name='own_name' direction='in'/>"
"			<arg type='i' name='ret' direction='out'/>"
"		</method>"
"	</interface>"
"</node>";

static int __esd_get_appid_by_pid(int pid, uid_t uid, char *app_id, int buf_size)
{
	int retval = ES_R_OK;
	int ret = 0;

	if (pid <= 0) {
		_E("invalid pid(%d)", pid);
		retval = ES_R_ERROR;
	} else if (uid <= 0) {
		_E("invalid uid(%d)", uid);
		retval = ES_R_ERROR;
	} else {
		ret = aul_app_get_appid_bypid_for_uid(pid, app_id, buf_size, (uid_t)uid);
		if (ret != AUL_R_OK) {
			_E("failed to get appid by pid");
			retval = ES_R_ERROR;
		}
		_D("pid(%d)-uid(%d)-appid(%s)", pid, uid, app_id);
	}

	return retval;
}

static int check_user_event_sender_valid(const char *event_name, const char *app_id)
{
	char *valid_name = NULL;
	char *temp_name = NULL;
	char *tmp = NULL;
	int retval = ES_R_OK;
	int len = 0;
	int valid_name_len = 0;

	temp_name = strdup(event_name);
	if (temp_name == NULL) {
		_E("out of memory");
		return ES_R_ENOMEM;
	}

	tmp = strrchr(temp_name, '.');
	if (tmp == NULL || strlen(tmp) == 0) {
		_E("invalid event name");
		FREE_AND_NULL(temp_name);
		return ES_R_EINVAL;
	}
	len = strlen(tmp);
	if (len <= 1 || len > 128) {
		_E("invalid length(%d) of user-defined name");
		FREE_AND_NULL(temp_name);
		return ES_R_EINVAL;
	}
	*tmp = '\0';

	_D("app_id(%s), len(%d)", app_id, strlen(app_id));

	valid_name_len = strlen(USER_EVENT_NAME_PREFIX) + strlen(app_id) + 1;
	valid_name = calloc(1, valid_name_len);
	if (valid_name == NULL) {
		_E("memory alloc failed");
		FREE_AND_NULL(temp_name);
		return ES_R_ENOMEM;
	}
	snprintf(valid_name, valid_name_len, "%s%s", USER_EVENT_NAME_PREFIX, app_id);
	_D("valid_name(%s)", valid_name);

	if (strcmp(temp_name, valid_name) != 0) {
		_E("appid misamatch");
		retval = ES_R_EINVAL;
	}

	FREE_AND_NULL(temp_name);
	FREE_AND_NULL(valid_name);

	return retval;
}

static void check_sender_valid_method_call(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	char *event_name = NULL;
	char app_id[128] = {0, };
	int event_sender_pid = 0;
	uid_t sender_uid = 0;

	g_variant_get(parameters, "(i&s)", &event_sender_pid, &event_name);
	_D("event_sender_pid(%d), event_name(%s)", event_sender_pid, event_name);

	sender_uid = (uid_t)__get_sender_uid(connection, sender);
	if (__esd_get_appid_by_pid(event_sender_pid, sender_uid, app_id, sizeof(app_id)) < 0) {
		result = ES_R_ERROR;
	} else {
		if (check_user_event_sender_valid(event_name, app_id) < 0) {
			_E("invalid sender");
			result = ES_R_EINVAL;
		} else {
			result = 1;
		}
	}

	param = g_variant_new("(is)", result, app_id);
	_D("event_name(%s), result(%d)", event_name, result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void check_send_event_valid_method_call(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	char *event_name = NULL;
	char app_id[128] = {0, };
	int sender_pid = 0;
	uid_t sender_uid = 0;

	g_variant_get(parameters, "(&s)", &event_name);
	_D("event_name(%s)", event_name);

	sender_pid = __get_sender_pid(connection, sender);
	sender_uid = (uid_t)__get_sender_uid(connection, sender);
	if (__esd_get_appid_by_pid(sender_pid, sender_uid, app_id, sizeof(app_id)) < 0) {
		result = ES_R_ERROR;
	} else {
		if (check_user_event_sender_valid(event_name, app_id) < 0) {
			_E("invalid sender");
			result = ES_R_EINVAL;
		} else {
			result = 1;
		}
	}

	param = g_variant_new("(i)", result);
	_D("event_name(%s), result(%d)", event_name, result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void get_trusted_peer_method_call(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	GVariantBuilder *builder = NULL;
	GHashTableIter iter;
	gpointer key, value;
	char *event_name = NULL;
	char app_id[128] = {0, };
	int sender_pid = 0;
	uid_t sender_uid = 0;
	int ret = 0;
	uid_t uid = 0;
	char *_appid = NULL;
	char *_busname = NULL;
	trusted_item *item;

	g_variant_get(parameters, "(&s)", &event_name);
	_D("event_name(%s)", event_name);

	sender_pid = __get_sender_pid(connection, sender);
	sender_uid = (uid_t)__get_sender_uid(connection, sender);
	if (__esd_get_appid_by_pid(sender_pid, sender_uid, app_id, sizeof(app_id)) < 0) {
		result = ES_R_ERROR;
	} else {
		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

		g_hash_table_iter_init(&iter, trusted_busname_table);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			item = (trusted_item *)value;
			uid = item->uid;
			_appid = item->app_id;
			_busname = item->bus_name;

			if (uid != GLOBAL_USER && uid != sender_uid)
				continue;

			ret = __esd_check_certificate_match(uid, _appid, sender_uid, app_id);
			if (ret == ES_R_OK)
				g_variant_builder_add(builder, "s", _busname);
		}

		result = 1;
	}

	param = g_variant_new("(ias)", result, builder);
	_D("result(%d)", result);
	g_dbus_method_invocation_return_value(invocation, param);
	if (builder)
		g_variant_builder_unref(builder);
}

static void setup_trusted_peer_method_call(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	char *event_name = NULL;
	char *destination_name = NULL;
	char app_id[128] = {0, };
	int sender_pid = 0;
	uid_t sender_uid = 0;
	int ret = 0;

	g_variant_get(parameters, "(&s&s)", &event_name, &destination_name);
	_D("event_name(%s), destination_name(%s)", event_name, destination_name);

	if (destination_name && destination_name[0] != '\0') {
		sender_pid = __get_sender_pid(connection, sender);
		sender_uid = (uid_t)__get_sender_uid(connection, sender);
		if (__esd_get_appid_by_pid(sender_pid, sender_uid, app_id, sizeof(app_id)) < 0) {
			result = ES_R_ERROR;
		} else {
			ret = __esd_trusted_busname_add_item(sender_uid, app_id, destination_name,
				sender_pid);
			if (ret < 0) {
				_E("failed to add trusted busname item");
				result = ES_R_ERROR;
			} else {
				result = 1;
			}
		}
	} else {
		_E("invalid destination name");
		result = ES_R_ERROR;
	}

	param = g_variant_new("(i)", result);
	_D("event_name(%s), result(%d)", event_name, result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void check_privilege_valid_method_call(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	char *event_name = NULL;
	char *privilege_name = NULL;
	char app_id[128] = {0, };
	int sender_pid = 0;
	uid_t sender_uid = 0;
	char *client = NULL;
	char *session = NULL;
	char *user = NULL;
	int ret = 0;

	g_variant_get(parameters, "(&s)", &event_name);
	__esd_check_privilege_name(event_name, &privilege_name);
	_D("event_name(%s), privilege_name(%s)", event_name, privilege_name);

	if (privilege_name) {
		sender_pid = __get_sender_pid(connection, sender);
		sender_uid = (uid_t)__get_sender_uid(connection, sender);
		if (__esd_get_appid_by_pid(sender_pid, sender_uid, app_id, sizeof(app_id)) < 0) {
			result = ES_R_ERROR;
		} else {
			ret = cynara_creds_gdbus_get_client(connection, sender, CLIENT_METHOD_DEFAULT, &client);
			if (ret != CYNARA_API_SUCCESS) {
				_E("failed to get client");
				result = ES_R_EINVAL;
				goto out;
			}

			ret = cynara_creds_gdbus_get_user(connection, sender, USER_METHOD_DEFAULT, &user);
			if (ret != CYNARA_API_SUCCESS) {
				_E("failed to get user");
				result = ES_R_EINVAL;
				goto out;
			}

			session = cynara_session_from_pid(sender_pid);
			if (session == NULL) {
				_E("failed to get session");
				result = ES_R_EINVAL;
				goto out;
			}

			_D("app_id(%s), client(%s), session(%s), user(%s)", app_id, client, session, user);
			if (__esd_check_valid_privilege_by_cynara(app_id, client, session, user, privilege_name))
				result = 1;
			else
				result = ES_R_EINVAL;
		}
	} else {
		result = 1;
	}

out:
	g_free(client);
	g_free(user);
	g_free(session);
	param = g_variant_new("(i)", result);
	_D("event_name(%s), result(%d)", event_name, result);
	g_dbus_method_invocation_return_value(invocation, param);
}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static void get_earlier_data_method_call(GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	char *event_name = NULL;
	bundle *b = NULL;
	bundle_raw *raw = NULL;
	int len = 0;
	earlier_item *item;

	g_variant_get(parameters, "(&s)", &event_name);

	if (event_name && strlen(event_name) > 0) {
		_D("event_name(%s)", event_name);
		result = ES_R_OK;
	} else {
		_E("invalid event_name(%s)", event_name);
		result = ES_R_ERROR;
	}

	item = (earlier_item *)g_hash_table_lookup(earlier_event_table, event_name);
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
}
#endif

static void keep_last_data_method_call(GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param;
	int result = ES_R_OK;
	char *event_name;
	char *own_name;
	struct __last_event_item *item;

	g_variant_get(parameters, "(&s&s)", &event_name, &own_name);

	if (!event_name || !own_name) {
		result = ES_R_ERROR;
		_E("invalid event_name and own_name");
		goto out;
	}

	item = (struct __last_event_item *)g_hash_table_lookup(user_last_event_table,
			event_name);
	if (!item) {
		item = calloc(1, sizeof(*item));
		if (!item) {
			result = ES_R_ERROR;
			goto out;
		}
		item->event_name = strdup(event_name);
		item->own_name = strdup(own_name);
		g_hash_table_insert(user_last_event_table,
				item->event_name, item);
	} else {
		free(item->own_name);
		item->own_name = strdup(own_name);
	}

out:
	param = g_variant_new("(i)", result);

	g_dbus_method_invocation_return_value(invocation, param);
}

static void check_last_data_method_call(GDBusConnection *connection,
		GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param;
	int result = ES_R_OK;
	char *event_name;
	char *own_name;
	struct __last_event_item *item;

	g_variant_get(parameters, "(&s&s)", &event_name, &own_name);

	if (!event_name || !own_name) {
		result = ES_R_ERROR;
		_E("invalid event_name and own_name");
		goto out;
	}

	item = (struct __last_event_item *)g_hash_table_lookup(user_last_event_table,
			event_name);
	if (item) {
		GDBusConnection *conn_system = NULL;
		GVariant *gv;
		bundle *b;
		bundle_raw *raw;
		int len;
		int ret;
		GError *error = NULL;

		conn_system = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (conn_system == NULL) {
			_E("failed to get system connection");
			if (error != NULL) {
				_E("error(%s)", error->message);
				g_error_free(error);
			}
		}

		b = bundle_create();
		bundle_add_str(b, EVT_VAL_ESD_EVENT_NAME, event_name);
		bundle_add_str(b, EVT_VAL_ESD_OWN_NAME, own_name);
		bundle_encode(b, &raw, &len);
		gv  = g_variant_new("(us)", len, raw);
		ret = g_dbus_connection_emit_signal(connection,
				item->own_name,
				SYS_EVENT_NAME_PREFIX,
				SYS_EVENT_OBJ_PATH,
				EVT_KEY_ESD_KEEP_DATA,
				gv,
				&error);
		if (ret == FALSE) {
			_E("Unable to connect to dbus: %s", error->message);
			g_error_free(error);
		}
		bundle_free_encoded_rawdata(&raw);
		bundle_free(b);
	}

out:
	param = g_variant_new("(i)", result);

	g_dbus_method_invocation_return_value(invocation, param);
}

static void handle_method_call(GDBusConnection *connection,
	const gchar *sender, const gchar *object_path,
	const gchar *interface_name, const gchar *method_name,
	GVariant *parameters, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	if (g_strcmp0(method_name, "CheckSenderValidation") == 0) {
		check_sender_valid_method_call(connection, sender, parameters, invocation);
	} else if (g_strcmp0(method_name, "GetTrustedPeerList") == 0) {
		get_trusted_peer_method_call(connection, sender, parameters, invocation);
	} else if (g_strcmp0(method_name, "SetupTrustedPeer") == 0) {
		setup_trusted_peer_method_call(connection, sender, parameters, invocation);
	} else if (g_strcmp0(method_name, "CheckPrivilegeValidation") == 0) {
		check_privilege_valid_method_call(connection, sender, parameters, invocation);
	} else if (g_strcmp0(method_name, "CheckUserSendValidation") == 0) {
		check_send_event_valid_method_call(connection, sender, parameters, invocation);
#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	} else if (g_strcmp0(method_name, "GetEarlierData") == 0) {
		get_earlier_data_method_call(parameters, invocation);
#endif
	} else if (g_strcmp0(method_name, "KeepLastData") == 0) {
		keep_last_data_method_call(parameters, invocation);
	} else if (g_strcmp0(method_name, "CheckLastData") == 0) {
		check_last_data_method_call(connection, parameters, invocation);
	}
}

static const GDBusInterfaceVTable interface_vtable = {
	handle_method_call,
	NULL,
	NULL
};

static void __esd_on_bus_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_I("bus acquired(%s)", name);

	guint reg_id = 0;
	GError *error = NULL;

	reg_id = g_dbus_connection_register_object(connection,
		ESD_OBJECT_PATH,
		introspection_data->interfaces[0],
		&interface_vtable,
		NULL, NULL, &error);
	if (reg_id == 0) {
		_E("g_dbus_connection_register_object error(%s)", error->message);
		g_error_free(error);
	}
}

static void __esd_on_name_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	bundle *b;

	_I("name acquired(%s)", name);

	__esd_check_trusted_events(connection, "ListNames");
	__esd_check_trusted_events(connection, "ListActivatableNames");

	b = bundle_create();
	bundle_add_str(b, EVT_KEY_ESD_STATUS, EVT_VAL_ESD_STARTED);
	eventsystem_send_system_event(SYS_EVENT_ESD_STATUS, b);
	bundle_free(b);

	__esd_register_vconf_callbacks();

	__esd_trusted_busname_print_items();

	__esd_start_sd_monitor();

	__esd_dbus_name_monitor(connection);
}

static void __esd_on_name_lost(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_E("name lost(%s)", name);
}

static int __esd_before_loop(void)
{
	int ret = 0;
	GError *error = NULL;
	guint owner_id = 0;

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	guint subscription_id = 0;
	int i;
	int size;
	char *event_name;
	int fd;
	int val;
	int status;
	int charger_status;
	int charge_now;
	earlier_item *item;

	earlier_event_table = g_hash_table_new(g_str_hash, g_str_equal);
	user_last_event_table = g_hash_table_new_full(g_str_hash,
			g_str_equal, NULL, (GDestroyNotify)free_saved_event);

	_I("register events for earlier_data");
	size = sizeof(earlier_event_list)/sizeof(*earlier_event_list);
	for (i = 0; i < size; i++) {
		event_name = (char *)earlier_event_list[i];
		_I("event_name(%s)", event_name);

		item = calloc(1, sizeof(earlier_item));
		if (item == NULL) {
			_E("memery alloc failed");
			return ES_R_ENOMEM;
		}
		item->event_name = strdup(event_name);
		if (item->event_name == NULL) {
			_E("out of memory");
			free(item);
			return ES_R_ENOMEM;
		}

		/* set initial data */
		if (strcmp(event_name, SYS_EVENT_BOOT_COMPLETED) == 0) {
			fd = open(ESD_BOOT_COMPLETED, O_RDONLY);
			if (fd < 0) {
				_D("open file error(%d)", fd);
			} else {
				item->earlier_data = bundle_create();
				bundle_add_str(item->earlier_data, EVT_KEY_BOOT_COMPLETED,
					EVT_VAL_BOOT_COMPLETED_TRUE);
				close(fd);
			}
		} else if (strcmp(event_name, SYS_EVENT_SYSTEM_SHUTDOWN) == 0) {
			ret = vconf_get_int(VCONFKEY_SYSMAN_POWER_OFF_STATUS, &val);
			if (ret != VCONF_OK) {
				_E("failed to get power_off status (%d)", ret);
			} else {
				if (val == VCONFKEY_SYSMAN_POWER_OFF_DIRECT ||
					val == VCONFKEY_SYSMAN_POWER_OFF_RESTART) {
					/* power-off requested */
					item->earlier_data = bundle_create();
					bundle_add_str(item->earlier_data, EVT_KEY_SYSTEM_SHUTDOWN,
						EVT_VAL_SYSTEM_SHUTDOWN_TRUE);
				}
			}
		} else if (strcmp(event_name, SYS_EVENT_LOW_MEMORY) == 0) {
			ret = vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &status);
			if (ret != VCONF_OK) {
				_E("failed to get low_memory status (%d)", ret);
			} else {
				item->earlier_data = bundle_create();
				if (status == VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING)
					bundle_add_str(item->earlier_data, EVT_KEY_LOW_MEMORY,
						EVT_VAL_MEMORY_SOFT_WARNING);
				else if (status == VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING)
					bundle_add_str(item->earlier_data, EVT_KEY_LOW_MEMORY,
						EVT_VAL_MEMORY_HARD_WARNING);
				else
					bundle_add_str(item->earlier_data, EVT_KEY_LOW_MEMORY,
						EVT_VAL_MEMORY_NORMAL);
			}
		} else if (strcmp(event_name, SYS_EVENT_BATTERY_CHARGER_STATUS) == 0) {
			ret = vconf_get_int(VCONFKEY_SYSMAN_CHARGER_STATUS, &charger_status);
			if (ret != VCONF_OK) {
				_E("failed to get charger_status (%d)", ret);
			} else {
				ret = vconf_get_int(VCONFKEY_SYSMAN_BATTERY_CHARGE_NOW, &charge_now);
				if (ret != VCONF_OK)
					_E("failed to get charge_now (%d)", ret);
			}

			if (ret == VCONF_OK) {
				item->earlier_data = bundle_create();
				if (charger_status == VCONFKEY_SYSMAN_CHARGER_CONNECTED) {
					if (charge_now == 0) {
						bundle_add_str(item->earlier_data,
							EVT_KEY_BATTERY_CHARGER_STATUS,
							EVT_VAL_BATTERY_CHARGER_DISCHARGING);
					} else {
						bundle_add_str(item->earlier_data,
							EVT_KEY_BATTERY_CHARGER_STATUS,
							EVT_VAL_BATTERY_CHARGER_CHARGING);
					}
				} else {
					bundle_add_str(item->earlier_data,
						EVT_KEY_BATTERY_CHARGER_STATUS,
						EVT_VAL_BATTERY_CHARGER_DISCONNECTED);
				}
			}
		}

		eventsystem_register_event(event_name, &subscription_id,
			(eventsystem_handler)__esd_event_handler, NULL);
		if (subscription_id == 0) {
			_E("signal subscription error, event_name(%s)", event_name);
			if (item->earlier_data)
				bundle_free(item->earlier_data);
			free(item->event_name);
			free(item);

			return ES_R_ERROR;
		} else {
			item->reg_id = subscription_id;
		}

		g_hash_table_insert(earlier_event_table, event_name, item);
	}

	__esd_earlier_table_print_items();
#endif

	event_launch_table = g_hash_table_new(g_str_hash, g_str_equal);
	trusted_busname_table = g_hash_table_new(g_str_hash, g_str_equal);

	/* gdbus setup for method call */
	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	if (!introspection_data) {
		_E("g_dbus_node_info_new_for_xml error(%s)", error->message);
		g_error_free(error);
		return ES_R_ERROR;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
		ESD_BUS_NAME,
		G_BUS_NAME_OWNER_FLAGS_NONE,
		__esd_on_bus_acquired,
		__esd_on_name_acquired,
		__esd_on_name_lost,
		NULL, NULL);
	if (!owner_id) {
		_E("g_bus_own_name error");
		g_dbus_node_info_unref(introspection_data);
		return ES_R_ERROR;
	}

	_I("esd before_loop done");

	return ES_R_OK;
}

static void __esd_pkgmgr_event_free(esd_pkgmgr_event *pkg_event)
{
	pkg_event->type = UNKNOWN;
	if (pkg_event->pkgid) {
		free(pkg_event->pkgid);
		pkg_event->pkgid = NULL;
	}
}

static int __esd_appcontrol_cb(const char *operation,
		const char *uri, const char *mime, void *data)
{
	esd_appctrl_cb_data *cb_data = (esd_appctrl_cb_data *)data;
	char *appid = NULL;
	char *pkgid = NULL;
	char *event_name = NULL;
	const char *prefix = "event://";
	uid_t uid = 0;

	if (cb_data == NULL) {
		_E("invalid data");
		return 0;
	}
	appid = cb_data->appid;
	pkgid = cb_data->pkgid;
	uid = cb_data->uid;

	_D("uid(%d), appid(%s), pkgid(%s), operation(%s), uri(%s), mime(%s)",
		uid, appid, pkgid, operation, uri, mime);

	if (!strcmp(operation, APPSVC_OPERATION_LAUNCH_ON_EVENT)) {
		if (!strncmp(uri, prefix, strlen(prefix))) {
			event_name = strdup(&uri[8]);
			if (event_name) {
				_D("appid(%s), event_name(%s)", appid, event_name);
				if (!__esd_check_event_launch_support(event_name)) {
					_E("failed to add item (not support event)");
				} else if (!__esd_check_app_privileged_event(uid, appid, pkgid, event_name)) {
					_E("failed to add item (no privilege)");
				} else {
					if (__esd_add_launch_item(uid, event_name, appid, pkgid))
						_E("failed to add item");
				}
				FREE_AND_NULL(event_name);
			} else {
				_E("out of memory");
			}
		} else {
			_E("Invalid uri(%s) for event_name", uri);
		}
	}

	return 0;
}

static int __esd_add_appinfo_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	char *appid = NULL;
	char *pkgid = NULL;
	int ret = 0;
	uid_t *p_uid = NULL;

	if (data == NULL) {
		_E("invalid data");
		return ES_R_ERROR;
	}

	p_uid = (uid_t *)data;

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret < 0) {
		_E("failed to get appid");
		return ES_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("failed to get appid");
		return ES_R_ERROR;
	}

	esd_appctrl_cb_data *cb_data = calloc(1, sizeof(esd_appctrl_cb_data));

	if (cb_data == NULL) {
		_E("memory alloc failed");
		return ES_R_ENOMEM;
	}
	cb_data->appid = strdup(appid);
	if (cb_data->appid == NULL) {
		_E("out_of_memory");
		FREE_AND_NULL(cb_data);
		return ES_R_ENOMEM;
	}
	cb_data->pkgid = strdup(pkgid);
	if (cb_data->pkgid == NULL) {
		_E("out_of_memory");
		FREE_AND_NULL(cb_data->appid);
		FREE_AND_NULL(cb_data);
		return ES_R_ENOMEM;
	}
	cb_data->uid = *p_uid;

	ret = pkgmgrinfo_appinfo_foreach_appcontrol(handle,
		(pkgmgrinfo_app_control_list_cb)__esd_appcontrol_cb, cb_data);

	FREE_AND_NULL(cb_data->pkgid);
	FREE_AND_NULL(cb_data->appid);
	FREE_AND_NULL(cb_data);

	if (ret < 0) {
		_E("failed to get appcontrol info");
		return ES_R_ERROR;
	}

	return ES_R_OK;
}

static int __esd_pkgmgr_event_callback(uid_t target_uid, int req_id,
		const char *pkg_type, const char *pkgid, const char *key,
		const char *val, const void *pmsg, void *data)
{
	esd_pkgmgr_event *pkg_event = (esd_pkgmgr_event *)data;
	pkgmgrinfo_pkginfo_h handle = NULL;
	int ret = 0;

	_D("target_uid(%d), req_id(%d), pkg_type(%s), pkgid(%s), key(%s), val(%s)",
		target_uid, req_id, pkg_type, pkgid, key, val);

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
			__esd_pkgmgr_event_free(pkg_event);
		}
	} else if (strcmp(key, "end") == 0 && strcmp(val, "ok") == 0) {
		if (pkg_event->type == INSTALL || pkg_event->type == UPDATE) {
			_D("install end (ok)");
			ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, target_uid, &handle);
			if (ret < 0) {
				_E("failed to get pkginfo");
				__esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
			ret = pkgmgrinfo_appinfo_get_usr_list(handle,
				PMINFO_ALL_APP, __esd_add_appinfo_handler, &target_uid, target_uid);
			if (ret < 0) {
				_E("failed to get appinfo");
				__esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
			ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			if (ret < 0) {
				_E("failed to destroy pkginfo");
				__esd_pkgmgr_event_free(pkg_event);
				return 0;
			}
		} else if (pkg_event->type == UNINSTALL) {
			_D("uninstall end (ok)");
			__esd_launch_table_remove_items(target_uid, pkgid);
			__esd_launch_table_print_items();
		}
		__esd_pkgmgr_event_free(pkg_event);
	} else if (strcmp(key, "end") == 0 && strcmp(val, "fail") == 0) {
		_E("pkg_event(%d) falied", pkg_event->type);
		__esd_pkgmgr_event_free(pkg_event);
	} else {
		if (strcmp(key, "install_percent") != 0)
			__esd_pkgmgr_event_free(pkg_event);
	}

	return 0;
}

static int __esd_init()
{
	int req_id = 0;
	int ret = 0;
	pkgmgr_client *client;
	esd_pkgmgr_event *pkg_event;

#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif
	ecore_init();

	__esd_init_cynara();

	client = pkgmgr_client_new(PC_LISTENING);
	if (client == NULL) {
		_E("set pkgmgr client failed");
		return ES_R_ERROR;
	}

	pkg_event = calloc(1, sizeof(esd_pkgmgr_event));
	if (pkg_event == NULL) {
		_E("memory alloc failed");
		ret = pkgmgr_client_free(client);
		if (ret != PKGMGR_R_OK)
			_E("pkgmgr_client_free failed(%d)", ret);

		return ES_R_ENOMEM;
	}

	req_id = pkgmgr_client_listen_status(client, __esd_pkgmgr_event_callback, pkg_event);
	if (req_id < 0) {
		_E("pkgmgr client listen failed");
		ret = pkgmgr_client_free(client);
		if (ret != PKGMGR_R_OK)
			_E("pkgmgr_client_free failed(%d)", ret);

		return ES_R_ERROR;
	}

	s_info.client = client;

	_I("esd init done");

	return 0;
}

static void __esd_remove_esd_list_item(gpointer data, gpointer user_data)
{
	esd_list_item_s *item = (esd_list_item_s *)data;

	free(item->app_id);
	free(item->pkg_id);
}

static void __esd_finalize(void)
{
	gpointer key;
	gpointer value;
	GHashTableIter iter;
	trusted_item *item;
	event_launch_item *el_item;
	int ret = 0;
#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	earlier_item *er_item;
#endif

	_D("esd finalize");

	__esd_stop_sd_monitor();

	if (trusted_busname_table) {
		g_hash_table_iter_init(&iter, trusted_busname_table);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			item = (trusted_item *)value;
			if (item) {
				free(item->app_id);
				free(item->bus_name);
				free(item);
			} else {
				_E("item is null");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(trusted_busname_table);
	}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	if (earlier_event_table) {
		g_hash_table_iter_init(&iter, earlier_event_table);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			er_item = (earlier_item *)value;
			if (er_item) {
				eventsystem_unregister_event(er_item->reg_id);
				free(er_item->event_name);
				bundle_free(er_item->earlier_data);
				free(er_item);
			} else {
				_E("ealier item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(earlier_event_table);
	}

	g_hash_table_destroy(user_last_event_table);
#endif

	if (event_launch_table) {
		g_hash_table_iter_init(&iter, event_launch_table);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			el_item = (event_launch_item *)value;
			if (el_item) {
				eventsystem_unregister_event(el_item->reg_id);
				free(el_item->event_name);
				g_list_foreach(el_item->app_list_evtlaunch,
					__esd_remove_esd_list_item, NULL);
				g_list_free(el_item->app_list_evtlaunch);
				free(el_item);
			} else {
				_E("item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(event_launch_table);
	}

	if (introspection_data)
		g_dbus_node_info_unref(introspection_data);

	if (s_info.client) {
		ret = pkgmgr_client_free(s_info.client);
		if (ret != PKGMGR_R_OK)
			_E("pkgmgr_client_free failed(%d)", ret);
	}

	__esd_finish_cynara();

	_D("esd finalize end");
}

int main(int argc, char *argv[])
{
	_I("event system daemon : main()");

	if (__esd_init() != 0) {
		_E("ESD Initialization failed!");
		return ES_R_ERROR;
	}

	if (__esd_before_loop() < 0) {
		_E("ESD failed!");
		__esd_finalize();
		return ES_R_ERROR;
	}

	ecore_main_loop_begin();

	_E("shutdown");

	__esd_finalize();

	ecore_shutdown();

	return 0;
}
