/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include <uci.h>
#include <uci_blob.h>

#include <target.h>

#include <curl/curl.h>

#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "nl80211.h"
#include "radio.h"
#include "vif.h"
#include "phy.h"
#include "log.h"
#include "evsched.h"
#include "uci.h"
#include "utils.h"
#include "radius_proxy.h"

ovsdb_table_t table_Radius_Proxy_Config;
struct blob_buf uci_buf = {};
struct blob_attr *n;

enum {
	RADIUS_PROX_CONFIG_NAME,
	RADIUS_PROX_CONFIG_LISTEN_UDP,
	RADIUS_PROXY_CA_CERT,
	RADIUS_PROXY_CLIENT_CERT,
	RADIUS_PROXY_CLIENT_KEY,
	RADIUS_PROXY_PASSPHRASE,
	RADIUS_PROXY_SERVER_NAME,
	RADIUS_PROXY_SERVER_TYPE,
	RADIUS_PROXY_SERVER_SECRET,
	RADIUS_PROXY_SERVER_STATUS,
	RADIUS_PROXY_SERVER_CERT_NAME_CHECK,
	RADIUS_PROXY_PORT,
	RADIUS_PROXY_REALM_NAME,
	RADIUS_PROXY_REALM_SERVER,
	__RADIUS_PROXY_MAX
};

static const struct blobmsg_policy radsec_proxy_policy[__RADIUS_PROXY_MAX] = {
		[RADIUS_PROX_CONFIG_NAME] = { .name = "name", BLOBMSG_TYPE_STRING },
		[RADIUS_PROX_CONFIG_LISTEN_UDP] = { .name = "ListenUDP", BLOBMSG_TYPE_ARRAY },
		[RADIUS_PROXY_CA_CERT] = { .name = "CACertificateFile", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_CLIENT_CERT] = { .name = "certificateFile", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_CLIENT_KEY] = { .name = "certificateKeyFile", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_PASSPHRASE] = { .name = "certificateKeyPassword", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_SERVER_NAME] = { .name = "name", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_SERVER_TYPE] = { .name = "type", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_SERVER_SECRET] = { .name = "secret", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_SERVER_STATUS] = { .name = "statusServer", BLOBMSG_TYPE_BOOL },
		[RADIUS_PROXY_SERVER_CERT_NAME_CHECK] = { .name = "certificateNameCheck", BLOBMSG_TYPE_BOOL },
		[RADIUS_PROXY_PORT] = { .name = "port", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_REALM_NAME] = { .name = "name", BLOBMSG_TYPE_STRING },
		[RADIUS_PROXY_REALM_SERVER] = { .name = "server", BLOBMSG_TYPE_ARRAY },
};

const struct uci_blob_param_list radius_proxy_param = {
	.n_params = __RADIUS_PROXY_MAX,
	.params = radsec_proxy_policy,
};

size_t file_write(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

static bool radsec_download_cert(char *cert_name, char *dir_name, char *cert_url)
{
	CURL *curl;
	FILE *fp;
	CURLcode res;
	char path[200];
	char name[32];
	char dir[32];

	strcpy(name, cert_name);
	strcpy(dir, dir_name);
	sprintf(path, "/usr/radsec/certs/%s/%s", dir, name);

	curl = curl_easy_init();
	if (curl)
	{
		fp = fopen(path,"wb");

		if (fp == NULL)
		{
			curl_easy_cleanup(curl);
			return false;
		}

		if (cert_url == NULL)
		{
			curl_easy_cleanup(curl);
			fclose(fp);
			return false;
		}

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
		curl_easy_setopt(curl, CURLOPT_URL, cert_url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		fclose(fp);
		return res;
	}

	return true;
}

static bool raidus_proxy_config_set( struct schema_Radius_Proxy_Config *old,
	struct schema_Radius_Proxy_Config *conf )
{
	int i=0;
	char path[200];

	blob_buf_init(&uci_buf, 0);
	n = blobmsg_open_array(&uci_buf,"ListenUDP");
	blobmsg_add_string(&uci_buf, NULL, "127.0.0.1:1812");
	blobmsg_close_array(&uci_buf, n);
	blob_to_uci_section(uci, "radsecproxy", NULL, "options", uci_buf.head, &radius_proxy_param, NULL);

	blob_buf_init(&uci_buf, 0);
	blobmsg_add_string(&uci_buf, "name", "localhost");
	blobmsg_add_string(&uci_buf, "type", "udp");
	blobmsg_add_string(&uci_buf, "secret", "secret");
	blob_to_uci_section(uci, "radsecproxy", NULL, "client", uci_buf.head, &radius_proxy_param, NULL);

	blob_buf_init(&uci_buf, 0);
	if (strlen(conf->server))
	{
		blobmsg_add_string(&uci_buf, "name", conf->server);
		blobmsg_add_string(&uci_buf, "type", "tls");
		blobmsg_add_string(&uci_buf, "secret", "radsec");
		blobmsg_add_bool(&uci_buf, "statusServer", 1);
		blobmsg_add_bool(&uci_buf, "certificateNameCheck", 0);
		blob_to_uci_section(uci, "radsecproxy", NULL, "server", uci_buf.head, &radius_proxy_param, NULL);
	}

	for (i = 0; i < conf->realm_len; i++)
	{
		blob_buf_init(&uci_buf, 0);
		blobmsg_add_string(&uci_buf, "name", conf->realm[i]);
		n = blobmsg_open_array(&uci_buf,"server");
		blobmsg_add_string(&uci_buf, NULL, conf->server);
		blobmsg_close_array(&uci_buf, n);
		blob_to_uci_section(uci, "radsecproxy", NULL, "realm", uci_buf.head, &radius_proxy_param, NULL);
	}

	if (conf->radsec)
	{
		radsec_download_cert("cacert.pem", conf->radius_config_name, conf->ca_cert);
		radsec_download_cert("clientcert.pem", conf->radius_config_name, conf->client_cert);
		radsec_download_cert("clientdec.key", conf->radius_config_name, conf->client_key);

		blob_buf_init(&uci_buf, 0);
		blobmsg_add_string(&uci_buf, "name", conf->radius_config_name);
		path[0] = '\0';
		sprintf(path, "/usr/radsec/certs/%s/cacert.pem", conf->radius_config_name);
		blobmsg_add_string(&uci_buf, "CACertificateFile", path);
		path[0] = '\0';
		sprintf(path, "/usr/radsec/certs/%s/clientcert.pem", conf->radius_config_name);
		blobmsg_add_string(&uci_buf, "certificateFile", path);
		path[0] = '\0';
		sprintf(path, "/usr/radsec/certs/%s/clientdec.key", conf->radius_config_name);
		blobmsg_add_string(&uci_buf, "certificateKeyFile", path);
		blob_to_uci_section(uci, "radsecproxy", NULL, "tls", uci_buf.head, &radius_proxy_param, NULL);
	}

	return true;
}

static bool radius_proxy_config_delete( struct schema_Radius_Proxy_Config *old )
{
	struct uci_package *radsecproxy;
	struct uci_element *e = NULL, *tmp = NULL;
	int ret=0;

	ret= uci_load(uci, "radsecproxy", &radsecproxy);
	if (ret) {
		LOGD("%s: uci_load() failed with rc %d", __func__, ret);
		return false;
	}
	uci_foreach_element_safe(&radsecproxy->sections, tmp, e) {
		struct uci_section *s = uci_to_section(e);
		if ((s == NULL) || (s->type == NULL)) continue;
		uci_section_del(uci, "radsecproxy", "radsecproxy", (char *)s->e.name, s->type);
	}
	uci_commit(uci, &radsecproxy, false);
	uci_unload(uci, radsecproxy);
	reload_config = 1;
	return true;
}

void callback_Radius_Proxy_Config(ovsdb_update_monitor_t *self,
				 struct schema_Radius_Proxy_Config *old,
				 struct schema_Radius_Proxy_Config *conf)
{
	switch (self->mon_type)
	{
	case OVSDB_UPDATE_NEW:
	case OVSDB_UPDATE_MODIFY:
		(void) raidus_proxy_config_set(old, conf);
		break;

	case OVSDB_UPDATE_DEL:
		(void) radius_proxy_config_delete(old);
		break;

	default:
		LOG(ERR, "Radius_Proxy_Config: unexpected mon_type %d %s", self->mon_type, self->mon_uuid);
		break;
	}	
	return;
}


