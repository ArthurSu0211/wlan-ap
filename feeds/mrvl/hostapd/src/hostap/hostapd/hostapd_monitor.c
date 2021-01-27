#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/select.h>
#include <syslog.h>
#include <stdarg.h>
#include "wps/wps_attr_parse.h"
#include "common/wpa_ctrl.h"

#define CONTROL_IFACE_PATH "/var/run/hostapd"
#define IFNAMSIZ 16
#define SYSLOG

const static int radio0_index_base = 17;
const static int radio1_index_base = 51;

struct hostapd_monitor {
	struct wpa_ctrl *monitor_conn;
	char ifname[IFNAMSIZ+1];
	int index;
};
static struct hostapd_monitor *vifs;
static int vif_cnt;

void debug_log(const char *fmt, ...)
{
	va_list logmsg;

	va_start(logmsg, fmt);
#ifdef SYSLOG
	syslog(LOG_DEBUG, fmt, logmsg);
#else
	printf(fmt, logmsg);
#endif
	va_end(logmsg);
}

int connect_to_hostapd(struct hostapd_monitor *vif)
{
	char path[256] = {0};
	static struct wpa_ctrl *monitor_conn = NULL;

	sprintf(path, "%s/%s", CONTROL_IFACE_PATH, vif->ifname);

	monitor_conn = wpa_ctrl_open(path);
	if (monitor_conn == NULL)
		return -1;

	if (wpa_ctrl_attach(monitor_conn) != 0) {
		wpa_ctrl_close(monitor_conn);
		monitor_conn = NULL;
		return -1;
	}

	vif->monitor_conn = monitor_conn;
	return 0;
}

void close_sockets(void)
{
	int i = 0;

	for (i = 0; i < vif_cnt; i++) {
		if (vifs[i].monitor_conn != NULL) {
			wpa_ctrl_close(vifs[i].monitor_conn);
			vifs[i].monitor_conn = NULL;
		}
	}
}

static int str_to_hex(char *string, unsigned char *cbuf, int len)  
{  
	char high, low;
	int idx, i = 0;

	for (idx = 0; idx < len; idx += 2) {
		high = string[idx];
		low = string[idx + 1];

		if(high >= '0' && high <= '9')  
			high = high - '0';  
		else if(high >= 'A' && high <= 'F')  
			high = high - 'A' + 10;  
		else if(high >= 'a' && high <= 'f')  
			high = high - 'a' + 10;  
		else  
			return -1;  

		if(low >= '0' && low <= '9')  
			low = low - '0';  
		else if(low >= 'A' && low <= 'F')  
			low = low - 'A' + 10;  
		else if(low >= 'a' && low <= 'f')  
			low = low - 'a' + 10;  
		else  
			return -1;  

		cbuf[i++] = high <<4 | low;  
	}  
	return 0;  
}  

static struct wpabuf * local_wpabuf_alloc(size_t len)
{
	struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf) + len);
	if (buf == NULL)
		return NULL;

	buf->size = len;
	buf->used = len;
	buf->buf = (u8 *) (buf + 1);
	return buf;
}

static void local_wpabuf_free(struct wpabuf *buf)
{
	if (buf == NULL)
		return;
	if (buf->flags & WPABUF_FLAG_EXT_DATA)
		os_free(buf->buf);
	os_free(buf);
}

static void run_cmd(char *cmd)
{
	FILE *pipe ;
	pipe = popen(cmd, "r");
	debug_log("run cmd: %s\n", cmd);

	if (pipe)
		pclose(pipe);
}

void handle_wps_event(int vif_index, char *event, int event_len)
{
	char *data = event + strlen(WPS_EVENT_NEW_AP_SETTINGS);
	int data_len = event_len - strlen(WPS_EVENT_NEW_AP_SETTINGS);
	char *cmd = NULL;
	char ssid[33] = {0};
	char key[65] = {0};
	u16 auth_type = 0;  
	struct wpabuf *msg;
	struct wps_parse_attr attr;

	if (vif_index == 0)
		return;

	msg = local_wpabuf_alloc(data_len/2);
	str_to_hex(data, msg->buf, strlen(data));

	wps_parse_msg(msg, &attr);
	if (attr.ssid_len) {
		strncpy(ssid, attr.ssid, attr.ssid_len);
		asprintf(&cmd, "uci set wireless.@wifi-iface[%d].ssid=%s", vif_index, ssid);
		run_cmd(cmd);
		if (cmd)
			os_free(cmd);
	}
	if (attr.network_key_len) {
		strncpy(key, attr.network_key, attr.network_key_len);
		asprintf(&cmd, "uci set wireless.@wifi-iface[%d].key=%s", vif_index, key);
		run_cmd(cmd);
		if (cmd)
			os_free(cmd);
	}
	auth_type = WPA_GET_BE16(attr.auth_type);
	if (auth_type & WPS_AUTH_WPA2PSK) {
		asprintf(&cmd, "uci set wireless.@wifi-iface[%d].encryption=psk2+ccmp",
				vif_index);
		run_cmd(cmd);
		if (cmd)
			os_free(cmd);
	} else if (auth_type & WPS_AUTH_WPAPSK) {
		asprintf(&cmd, "uci set wireless.@wifi-iface[%d].encryption=psk+tkip",
				vif_index);
		run_cmd(cmd);
		if (cmd)
			os_free(cmd);
	} else if (auth_type & (WPS_AUTH_WPAPSK|WPS_AUTH_WPA2PSK)) {
		asprintf(&cmd, "uci set wireless.@wifi-iface[%d].encryption="
				"psk-mixed+tkip+ccmp", vif_index);
		run_cmd(cmd);
		if (cmd)
			os_free(cmd);
	}
	run_cmd("uci commit wireless");

	if (msg)
		local_wpabuf_free(msg);
}

int wait_for_event(char *buf, size_t buflen)
{
	int res;
	struct pollfd rfds[vif_cnt];
	int i;
	size_t nread = buflen -1;

	memset(rfds, 0, vif_cnt * sizeof(struct pollfd));
	for (i = 0; i < vif_cnt; i++) {
		rfds[i].fd =  wpa_ctrl_get_fd(vifs[i].monitor_conn);
		rfds[i].events |= POLLIN;
	}
	res = poll(rfds, vif_cnt, -1);
	if (res < 0) {
		debug_log("Error poll = %d", res);
		return res;
	}

	for (i = 0; i < vif_cnt; i++) {
		if (rfds[i].revents & POLLIN) {
			memset(buf, 0, buflen);
			res = wpa_ctrl_recv(vifs[i].monitor_conn, buf, &nread);
			if (!res && nread > 0) {
				/*
				 * Events strings are in the format
				 *
				 *	   <N>CTRL-EVENT-XXX
				 *
				 * where N is the message level in numerical form (0=VERBOSE, 1=DEBUG,
				 * etc.) and XXX is the event name. The level information is not useful
				 * to us, so strip it off.
				 */
				if (buf[0] == '<') {
					char *match = strchr(buf, '>');
					if (match != NULL) {
						nread -= (match+1-buf);
						memmove(buf, match+1, nread+1);
					}
				}
				if (strncmp(buf, WPS_EVENT_NEW_AP_SETTINGS,
							strlen(WPS_EVENT_NEW_AP_SETTINGS)) == 0
						&& nread > strlen(WPS_EVENT_NEW_AP_SETTINGS))
					handle_wps_event(vifs[i].index, buf, nread);
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	char buf[256];
	int i;
	int ret;

	vif_cnt = argc - 1;
	vifs = os_malloc(vif_cnt * sizeof(struct hostapd_monitor));

	for (i = 0; i < vif_cnt; i++) {
		strncpy(vifs[i].ifname, argv[i+1], IFNAMSIZ);

		if (strncmp(vifs[i].ifname, "wdev0", 5) == 0)
			vifs[i].index = radio0_index_base + atoi(vifs[i].ifname+strlen("wdev0ap"));
		else if (strncmp(vifs[i].ifname, "wdev1", 5) == 0)
			vifs[i].index = radio1_index_base + atoi(vifs[i].ifname+strlen("wdev1ap"));
		else
			vifs[i].index = 0;

		connect_to_hostapd(&vifs[i]);
	}

	while(1) {
		ret = wait_for_event(buf, sizeof(buf));
		if (ret != 0 )
			break;
	}

cleanup:
	close_sockets();
	os_free(vifs);
	return 0;
}
