#include <stdio.h>
#include <glib.h>
#include <stdio.h>
#include <glib.h>
#include <dlog.h>
#include <vconf.h>
#include <bundle.h>
#include <eventsystem.h>

#include "eventsystem_daemon.h"

/* table item : sent system-event by esd */
static GHashTable *esd_sent_table;

typedef struct __esd_sent_table_item {
	char *event_name;
	bundle *event_data;
} esd_sent_item;

struct esd_vconf_handler {
	const char *key;
	void (*esd_vconfcb_fn) (keynode_t *node, void *user_data);
};

static int __esd_event_data_compare(bundle *b1, bundle *b2, const char *key)
{
	int ret = 0;
	int tmp1 = 0;
	int tmp2 = 0;
	char *str1 = NULL;
	char *str2 = NULL;

	if (bundle_get_count(b1) == bundle_get_count(b2)) {
		tmp1 = bundle_get_str(b1, key, &str1);
		tmp2 = bundle_get_str(b2, key, &str2);
		if (tmp1 == BUNDLE_ERROR_NONE && tmp2 == BUNDLE_ERROR_NONE) {
			if (strcmp(str1, str2) != 0) {
				_D("new event_data : value check");
				ret = 1;
			}
		}
	} else {
		_D("new event_data : bundle_count check");
		ret = 1;
	}

	if (ret == 0) {
		_D("same event_data");
	}

	return ret;
}

static int __esd_send_system_event(const char *event_name, bundle *b, const char *key)
{
	int ret = ES_R_OK;

	esd_sent_item *item =
		(esd_sent_item *)g_hash_table_lookup(esd_sent_table, event_name);

	if (item && __esd_event_data_compare(item->event_data, b, key) == 0) {
		_D("skip send: same with previous data");
	} else {
		ret = eventsystem_send_system_event(event_name, b);
		if (ret != ES_R_OK) {
			_E("failed to send event");
			goto out;
		}

		if (item) {
			bundle_free(item->event_data);
			item->event_data = bundle_dup(b);
		} else {
			item = calloc(1, sizeof(esd_sent_item));
			if (item == NULL) {
				_E("memory alloc failed");
				ret = ES_R_ERROR;
				goto out;
			}
			item->event_name = strdup(event_name);
			if (item->event_name == NULL) {
				_E("out of memory");
				FREE_AND_NULL(item);
				ret = ES_R_ERROR;
				goto out;
			}
			item->event_data = bundle_dup(b);
		}

		g_hash_table_insert(esd_sent_table, item->event_name, item);
	}

out:
	return ret;
}

static void __esd_vconfcb_location_use_mylocation(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_int(VCONFKEY_LOCATION_USE_MY_LOCATION, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_LOCATION_ENABLE_STATE;

	if (enabled) {
		val = EVT_VAL_LOCATION_ENABLED;
	} else {
		val = EVT_VAL_LOCATION_DISABLED;
	}

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_LOCATION_ENABLE_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_location_enabled(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_int(VCONFKEY_LOCATION_ENABLED, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_GPS_ENABLE_STATE;

	if (enabled) {
		val = EVT_VAL_GPS_ENABLED;
	} else {
		val = EVT_VAL_GPS_DISABLED;
	}

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_GPS_ENABLE_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_location_network_enabled(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_int(VCONFKEY_LOCATION_NETWORK_ENABLED, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_NPS_ENABLE_STATE;

	if (enabled) {
		val = EVT_VAL_NPS_ENABLED;
	} else {
		val = EVT_VAL_NPS_DISABLED;
	}

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_NPS_ENABLE_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_language_set(keynode_t *node, void *user_data)
{
	char *str = 0;
	bundle *b = NULL;
	const char *key = NULL;

	_D("vconfcb called");

	str = vconf_get_str(VCONFKEY_LANGSET);
	if (str == NULL) {
		_E("failed to get vconf str");
		return;
	}

	key = EVT_KEY_LANGUAGE_SET;

	b = bundle_create();
	bundle_add_str(b, key, str);

	if (__esd_send_system_event(SYS_EVENT_LANGUAGE_SET, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_hour_format(keynode_t *node, void *user_data)
{
	int ret = 0;
	int hours = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_int(VCONFKEY_REGIONFORMAT_TIME1224, &hours);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_HOUR_FORMAT;

	if (hours == VCONFKEY_TIME_FORMAT_24)
		val = EVT_VAL_HOURFORMAT_24;
	else
		val = EVT_VAL_HOURFORMAT_12;

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_HOUR_FORMAT, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_region_format(keynode_t *node, void *user_data)
{
	char *str = 0;
	bundle *b = NULL;
	const char *key = NULL;

	_D("vconfcb called");

	str = vconf_get_str(VCONFKEY_REGIONFORMAT);
	if (str == NULL) {
		_E("failed to get vconf str");
		return;
	}

	key = EVT_KEY_REGION_FORMAT;

	b = bundle_create();
	bundle_add_str(b, key, str);

	if (__esd_send_system_event(SYS_EVENT_REGION_FORMAT, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_vibration_status(keynode_t *node, void *user_data)
{
	int ret = 0;
	int vibration_on = 0;
	int sound_on = 0;
	bundle *b = NULL;
	char *key = NULL;
	char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_bool(VCONFKEY_SETAPPL_VIBRATION_STATUS_BOOL, &vibration_on);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	ret = vconf_get_bool(VCONFKEY_SETAPPL_SOUND_STATUS_BOOL, &sound_on);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	if (vibration_on) {
		key = EVT_KEY_VIBRATION_STATE;
		val = EVT_VAL_VIBRATION_ON;
		b = bundle_create();
		bundle_add_str(b, key, val);
		if (__esd_send_system_event(SYS_EVENT_VIBRATION_STATE, b, key) != ES_R_OK) {
			_E("failed to send event");
		}
		if (b) {
			bundle_free(b);
		}

		key = EVT_KEY_SILENT_MODE;
		val = EVT_VAL_SILENTMODE_OFF;
		b = bundle_create();
		bundle_add_str(b, key, val);
		if (__esd_send_system_event(SYS_EVENT_SILENT_MODE, b, key) != ES_R_OK) {
			_E("failed to send event");
		}
		if (b) {
			bundle_free(b);
		}
	} else {
		key = EVT_KEY_VIBRATION_STATE;
		val = EVT_VAL_VIBRATION_OFF;
		b = bundle_create();
		bundle_add_str(b, key, val);
		if (__esd_send_system_event(SYS_EVENT_VIBRATION_STATE, b, key) != ES_R_OK) {
			_E("failed to send event");
		}
		if (b) {
			bundle_free(b);
		}

		if (!sound_on) {
			key = EVT_KEY_SILENT_MODE;
			val = EVT_VAL_SILENTMODE_ON;
			b = bundle_create();
			bundle_add_str(b, key, val);
			if (__esd_send_system_event(SYS_EVENT_SILENT_MODE, b, key) != ES_R_OK) {
				_E("failed to send event");
			}
			if (b) {
				bundle_free(b);
			}
		}
	}
}

static void __esd_vconfcb_sound_status(keynode_t *node, void *user_data)
{
	int ret = 0;
	int vibration_on = 0;
	int sound_on = 0;
	bundle *b = NULL;
	char *key = NULL;
	char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_bool(VCONFKEY_SETAPPL_VIBRATION_STATUS_BOOL, &vibration_on);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	ret = vconf_get_bool(VCONFKEY_SETAPPL_SOUND_STATUS_BOOL, &sound_on);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	if (sound_on) {
		key = EVT_KEY_VIBRATION_STATE;
		val = EVT_VAL_VIBRATION_OFF;
		b = bundle_create();
		bundle_add_str(b, key, val);
		if (__esd_send_system_event(SYS_EVENT_VIBRATION_STATE, b, key) != ES_R_OK) {
			_E("failed to send event");
		}
		if (b) {
			bundle_free(b);
		}

		key = EVT_KEY_SILENT_MODE;
		val = EVT_VAL_SILENTMODE_OFF;
		b = bundle_create();
		bundle_add_str(b, key, val);
		if (__esd_send_system_event(SYS_EVENT_SILENT_MODE, b, key) != ES_R_OK) {
			_E("failed to send event");
		}
		if (b) {
			bundle_free(b);
		}
	} else {
		if (!vibration_on) {
			key = EVT_KEY_SILENT_MODE;
			val = EVT_VAL_SILENTMODE_ON;
			b = bundle_create();
			bundle_add_str(b, key, val);
			if (__esd_send_system_event(SYS_EVENT_SILENT_MODE, b, key) != ES_R_OK) {
				_E("failed to send event");
			}
			if (b) {
				bundle_free(b);
			}
		}
	}
}

static void __esd_vconfcb_auto_rotate(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_SCREEN_AUTOROTATE_STATE;

	if (enabled)
		val = EVT_VAL_SCREEN_AUTOROTATE_ON;
	else
		val = EVT_VAL_SCREEN_AUTOROTATE_OFF;

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_SCREEN_AUTOROTATE_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_mobiledata_state(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_bool(VCONFKEY_3G_ENABLE, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_MOBILE_DATA_STATE;

	if (enabled)
		val = EVT_VAL_MOBILE_DATA_ON;
	else
		val = EVT_VAL_MOBILE_DATA_OFF;

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_MOBILE_DATA_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_roaming_state(keynode_t *node, void *user_data)
{
	int ret = 0;
	int enabled = 0;
	bundle *b = NULL;
	const char *key = NULL;
	const char *val = NULL;

	_D("vconfcb called");

	ret = vconf_get_bool(VCONFKEY_SETAPPL_STATE_DATA_ROAMING_BOOL, &enabled);
	if (ret != VCONF_OK) {
		_E("failed to get vconf (%d)", ret);
		return;
	}

	key = EVT_KEY_DATA_ROAMING_STATE;

	if (enabled)
		val = EVT_VAL_DATA_ROAMING_ON;
	else
		val = EVT_VAL_DATA_ROAMING_OFF;

	b = bundle_create();
	bundle_add_str(b, key, val);

	if (__esd_send_system_event(SYS_EVENT_DATA_ROAMING_STATE, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static void __esd_vconfcb_font_set(keynode_t *node, void *user_data)
{
	char *str = 0;
	bundle *b = NULL;
	const char *key = NULL;

	_D("vconfcb called");

	str = vconf_get_str(VCONFKEY_SETAPPL_ACCESSIBILITY_FONT_NAME);
	if (str == NULL) {
		_E("failed to get vconf str");
		return;
	}

	key = EVT_KEY_FONT_SET;

	b = bundle_create();
	bundle_add_str(b, key, str);

	if (__esd_send_system_event(SYS_EVENT_FONT_SET, b, key) != ES_R_OK) {
		_E("failed to send event");
	}

	if (b) {
		bundle_free(b);
	}
}

static struct esd_vconf_handler vconf_callbacks[] = {
	{VCONFKEY_LOCATION_USE_MY_LOCATION, __esd_vconfcb_location_use_mylocation},
	{VCONFKEY_LOCATION_ENABLED, __esd_vconfcb_location_enabled},
	{VCONFKEY_LOCATION_NETWORK_ENABLED, __esd_vconfcb_location_network_enabled},
	{VCONFKEY_LANGSET, __esd_vconfcb_language_set},
	{VCONFKEY_REGIONFORMAT_TIME1224, __esd_vconfcb_hour_format},
	{VCONFKEY_REGIONFORMAT, __esd_vconfcb_region_format},
	{VCONFKEY_SETAPPL_VIBRATION_STATUS_BOOL, __esd_vconfcb_vibration_status},
	{VCONFKEY_SETAPPL_SOUND_STATUS_BOOL, __esd_vconfcb_sound_status},
	{VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, __esd_vconfcb_auto_rotate},
	{VCONFKEY_3G_ENABLE, __esd_vconfcb_mobiledata_state},
	{VCONFKEY_SETAPPL_STATE_DATA_ROAMING_BOOL, __esd_vconfcb_roaming_state},
	{VCONFKEY_SETAPPL_ACCESSIBILITY_FONT_NAME, __esd_vconfcb_font_set},
};

static int vconfcbs_size = sizeof(vconf_callbacks)/sizeof(struct esd_vconf_handler);

int __esd_register_vconf_callbacks(void)
{
	int i = 0;
	int ret = 0;
	int result = ES_R_OK;

#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	esd_sent_table = g_hash_table_new(g_str_hash, g_str_equal);

	_D("vconf callbacks size(%d)", vconfcbs_size);
	for (i = 0; i < vconfcbs_size; i++) {
		ret = vconf_notify_key_changed(vconf_callbacks[i].key,
			vconf_callbacks[i].esd_vconfcb_fn, NULL);
		if (ret != VCONF_OK) {
			_E("failed to register vconf callback (%s)", vconf_callbacks[i].key);
			result = ES_R_ERROR;
			break;
		}
	}

	return result;
}

