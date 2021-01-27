/*
 * Driver interaction with Linux nl80211/cfg80211 - marvell specific
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <fcntl.h>

#include "utils/common.h"
#include "driver_nl80211.h"
#include "common/mrvl-vendor.h"
#include "ap/hostapd.h"

#ifdef CONFIG_WLS_PF
struct _bitfield {
	u8 *bits;
	size_t max_bits;
};
static struct _bitfield *capa_bits;
static struct _bitfield *marvell_ext_capa_mask;

static struct _bitfield * _bitfield_alloc(size_t max_bits)
{
	struct _bitfield *bf;
	bf = os_zalloc(sizeof(*bf) + (max_bits + 7) / 8);
	if (bf == NULL)
		return NULL;
	bf->bits = (u8 *) (bf + 1);
	bf->max_bits = max_bits;
	return bf;
}

static void _bitfield_free(struct _bitfield *bf)
{
	os_free(bf);
}

static void _bitfield_set(struct _bitfield *bf, size_t bit)
{
	if (bit >= bf->max_bits)
		return;
	bf->bits[bit / 8] |= BIT(bit % 8);
}

static void _bitfield_clear(struct _bitfield *bf, size_t bit)
{
	if (bit >= bf->max_bits)
		return;
	bf->bits[bit / 8] &= ~BIT(bit % 8);
}
#endif

static const char *ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}

static int marvell_send_mlme(void *priv, struct mwl_mlme *mlme)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
			nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
			nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SEND_MLME) ||
			!(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
			nla_put(msg, MWL_VENDOR_ATTR_MLME, sizeof(struct mwl_mlme), mlme)) {
		wpa_printf(MSG_ERROR,
				"%s: err in adding vendor_cmd and vendor_data",
				__func__);
		nlmsg_free(msg);
		return -1;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
				"%s: err in send_and_recv_msgs", __func__);
		return ret;
	}
	nlmsg_free(msg);
	return 0;
}

static int marvell_set_appie(void *priv, struct mwl_appie *appie)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SET_APPIE) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put(msg, MWL_VENDOR_ATTR_APPIE, sizeof(struct mwl_appie), appie)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		nlmsg_free(msg);
		return -1;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: %d err in send_and_recv_msgs", __func__, ret);
		return ret;
	}
	nlmsg_free(msg);
	return 0;
}

int marvell_commit(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	if (!(msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_VENDOR)) ||
		nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
		nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, MWL_VENDOR_CMD_COMMIT))
		goto fail;

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret)
		wpa_printf(MSG_DEBUG, "nl80211: vendor command failed err=%d",
			   ret);
	return ret;

fail:
	nlmsg_free(msg);
	return -ENOBUFS;
}

void marvell_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
	wpa_printf(MSG_DEBUG, "%s\n", __FUNCTION__);
#ifdef CONFIG_WLS_PF
	capa_bits = _bitfield_alloc(10*8);
	marvell_ext_capa_mask = _bitfield_alloc(10*8);
#endif
}

void marvell_deinit(void* priv)
{
	struct mwl_appie appie;
	memset(&(appie.buf[0]), 0x00, IE_BUF_LEN);
	appie.len = IE_BUF_LEN;
	marvell_commit(priv);
#ifdef CONFIG_WLS_PF
	_bitfield_free(capa_bits);
	_bitfield_free(marvell_ext_capa_mask);
#endif
}

int marvell_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
		  int reassoc, u16 status_code, const u8 *ie, size_t len)
{
	struct mwl_mlme mlme;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d reassoc %d",
		   __func__, ether_sprintf(addr), status_code, reassoc);

	if (reassoc)
		mlme.op = MWL_MLME_SET_REASSOC;
	else
		mlme.op = MWL_MLME_SET_ASSOC;
	mlme.reason = status_code;
	memcpy(mlme.macaddr, addr, ETH_ALEN);
	mlme.optie_len = len;
	if (len) {
		if (len < 256) {
			os_memcpy(mlme.optie, ie, len);
		} else {
			wpa_printf(MSG_DEBUG, "%s: Not enough space to copy "
				   "opt_ie STA (addr " MACSTR " reason %d, "
				   "ie_len %d)",
				   __func__, MAC2STR(addr), status_code,
				   (int) len);
			return -1;
		}
	}
	ret = marvell_send_mlme(priv, &mlme);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to assoc STA (addr " MACSTR
			   " reason %d)",
			   __func__, MAC2STR(addr), status_code);
	}
	return ret;
}

int marvell_sta_auth(void *priv,
            struct wpa_driver_sta_auth_params *param)
{
	struct mwl_mlme mlme;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d",
		   __func__, ether_sprintf(param->addr), param->status);

	mlme.op = MWL_MLME_SET_AUTH;
	mlme.reason = param->status;
	mlme.seq = param->seq;
	memcpy(mlme.macaddr, param->addr, ETH_ALEN);
	mlme.optie_len = param->len;
	if (param->len) {
		if (param->len < 256) {
			os_memcpy(mlme.optie, param->ie, param->len);
		} else {
			wpa_printf(MSG_DEBUG, "%s: Not enough space to copy "
				   "opt_ie STA (addr " MACSTR " reason %d, "
				   "ie_len %d)",
				   __func__, MAC2STR(param->addr), param->status,
				   (int) param->len);
			return -1;
		}
	}
	ret = marvell_send_mlme(priv, &mlme);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to auth STA (addr " MACSTR
			   " reason %d)",
			   __func__, MAC2STR(param->addr), param->status);
	}
	return ret;
}

#if defined(CONFIG_IEEE80211R) || defined(CONFIG_MULTI_AP)
int marvell_add_sta_node(void *priv, const u8 *addr, u16 auth_alg)
{
	struct mwl_mlme mlme;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: addr=%s auth_alg=%d",
		   __func__, ether_sprintf(addr), auth_alg);

	mlme.op = MWL_MLME_AUTHORIZE;
	mlme.reason = auth_alg;
	memcpy(mlme.macaddr, addr, ETH_ALEN);

	ret = marvell_send_mlme(priv, &mlme);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to add STA node (addr " MACSTR
			   " auth_alg %d)",
			   __func__, MAC2STR(addr), auth_alg);
	}
	return ret;
}

int marvell_set_opt_ie(void *priv, const u8 *ie, size_t ie_len)
{
	struct mwl_appie appie;

	appie.len = ie_len;

	if (ie != NULL && ie_len != 0) {
		memcpy(&(appie.buf[0]), ie , ie_len);
		switch(ie[0]) {
			case WLAN_EID_VENDOR_SPECIFIC:
				appie.type = MWL_OPTIE_BEACON_NORSN;
				marvell_set_appie(priv, &appie);
				appie.type = MWL_OPTIE_PROBE_RESP_NORSN;
				marvell_set_appie(priv, &appie);
				break;
			default:
				appie.type = MWL_OPTIE_BEACON_INCL_RSN;
				marvell_set_appie(priv, &appie);
				appie.type = MWL_OPTIE_PROBE_RESP_INCL_RSN;
				marvell_set_appie(priv, &appie);
				break;
		}
	} else {
		memset(&(appie.buf[0]), 0x00, IE_BUF_LEN);
		appie.len = IE_BUF_LEN;
		appie.type = MWL_OPTIE_BEACON_INCL_RSN;
		marvell_set_appie(priv, &appie);
		appie.type = MWL_OPTIE_PROBE_RESP_INCL_RSN;
		marvell_set_appie(priv, &appie);
	}
	return 0;
}
#endif /* CONFIG_IEEE80211R || CONFIG_MULTI_AP */

#ifdef CONFIG_WLS_PF
int marvell_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	struct i802_bss *bss = priv;
	struct hostapd_data *hapd = (struct hostapd_data *)(bss->drv->ctx);
	wpa_printf(MSG_DEBUG, "%s %d\n", __func__, hapd->conf->interworking);

	if (hapd->conf->interworking) {
		_bitfield_set(marvell_ext_capa_mask, 14);
		_bitfield_set(marvell_ext_capa_mask, 15);
		_bitfield_set(marvell_ext_capa_mask, 31);
		_bitfield_set(marvell_ext_capa_mask, 70);
		_bitfield_set(marvell_ext_capa_mask, 71);
		_bitfield_clear(capa_bits, 14);
		_bitfield_clear(capa_bits, 15);
		_bitfield_clear(capa_bits, 31);
		_bitfield_clear(capa_bits, 70);
		_bitfield_clear(capa_bits, 71);
	} else {
		_bitfield_clear(marvell_ext_capa_mask, 14);
		_bitfield_clear(marvell_ext_capa_mask, 15);
		_bitfield_clear(marvell_ext_capa_mask, 31);
		_bitfield_clear(marvell_ext_capa_mask, 70);
		_bitfield_clear(marvell_ext_capa_mask, 71);

		_bitfield_set(capa_bits, 14);
		_bitfield_set(capa_bits, 15);
		_bitfield_set(capa_bits, 31);
		_bitfield_set(capa_bits, 70);
		_bitfield_set(capa_bits, 71);
	}
	capa->extended_capa = capa_bits->bits;
	capa->extended_capa_mask = marvell_ext_capa_mask->bits;
	capa->extended_capa_len = 10;

	return 0;
}
#endif

int marvell_set_bandsteer(void *priv, int enable)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SET_BANDSTEER) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put_u32(msg, MWL_VENDOR_ATTR_BANDSTEER, enable)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		nlmsg_free(msg);
		return -1;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
		return ret;
	}
	nlmsg_free(msg);
	return 0;
}

int marvell_send_mgmt(void *priv, const u8 *data, size_t data_len,
			 int noack, unsigned int freq, const u16 *csa_offs,
			 size_t csa_offs_len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	struct mwl_mgmt *mgmt;
	mgmt = os_zalloc(data_len + 2);
	if (mgmt == NULL)
		return -1;

	mgmt->len = data_len;
	memcpy(mgmt->buf, data, data_len);

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SEND_MGMT) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put(msg, MWL_VENDOR_ATTR_MGMT, mgmt->len+2, mgmt)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		ret = -1;
		goto fail;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
		return ret;
	}
fail:
	os_free(mgmt);
	nlmsg_free(msg);
	return ret;
}

int marvell_updown_vap(void *priv, int up, const char *sta_ifname)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;

	if (!is_ap_interface(drv->nlmode))
		return 0;
	if (!os_strcmp(bss->ifname, "wdev0") || !os_strcmp(bss->ifname, "wdev1"))
		return 0;
	if (!sta_ifname)
		return 0;

	/* only up or down the same radio's vap with sta */
	if (os_strncmp(bss->ifname, sta_ifname, 5) == 0)
		linux_set_iface_flags(bss->drv->global->ioctl_sock,
					     bss->ifname, up);

	return 0;
}

int marvell_do_acs(void *priv, struct drv_acs_params *params)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	if (!(msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_VENDOR)) ||
		nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
		nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, MWL_VENDOR_CMD_DO_ACS))
		goto fail;

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret)
		wpa_printf(MSG_DEBUG, "nl80211: vendor command failed err=%d",
			   ret);
	return ret;

fail:
	nlmsg_free(msg);
	return -ENOBUFS;
}

int marvell_set_rrm(void *priv, u8 enable)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SET_RRM) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put_u8(msg, MWL_VENDOR_ATTR_RRM, enable)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		nlmsg_free(msg);
		return -1;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
		return ret;
	}
	nlmsg_free(msg);
	return 0;
}

#ifdef CONFIG_MULTI_AP
static int get_multiap_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	u8 *data = NULL;
	size_t len = 0;
	u8 *multi_ap = arg;
	int ret;

	if (!multi_ap)
		return NL_SKIP;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_VENDOR_DATA])
		return NL_SKIP;

	data = nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
	len = nla_len(tb[NL80211_ATTR_VENDOR_DATA]);

	if ((!data) || (!len))
		return NL_SKIP;

	wpa_hexdump(MSG_MSGDUMP, "nl80211: Vendor data", data, len);

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, (struct nlattr *)data,
	                len, NULL);
	if (ret)
		return NL_SKIP;

	if (tb[MWL_VENDOR_ATTR_MULTIAP])
		*multi_ap = nla_get_u8(tb[MWL_VENDOR_ATTR_MULTIAP]);

	return NL_SKIP;
}

u8 marvell_get_multiap(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	u8 multi_ap;

	if (!(msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		        MWL_VENDOR_CMD_GET_MULTIAP)) {
		nlmsg_free(msg);
		return 0;
	}

	ret = send_and_recv_msgs(drv, msg, get_multiap_handler, &multi_ap);
	msg = NULL;
	if (ret)
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
	return multi_ap;
}
#endif /* CONFIG_MULTI_AP */

int marvell_set_ssid(void *priv, const u8 *buf, int len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	/* Avoid set SSID redundantly, SSID will be set into driver at NL80211_CMD_NEW_BEACON */
	if (bss->beacon_set == 0)
		return 0;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SET_SSID) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put(msg, MWL_VENDOR_ATTR_SSID, len, buf)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		nlmsg_free(msg);
		return 0;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
		return 0;
	}
	nlmsg_free(msg);

	marvell_commit(priv);

	return ret;
}

static int get_ssid_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	u8 *data = NULL;
	size_t len = 0;
	u8 *ssid = arg;
	int ret;

	if (!ssid)
		return NL_SKIP;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_VENDOR_DATA])
		return NL_SKIP;

	data = nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
	len = nla_len(tb[NL80211_ATTR_VENDOR_DATA]);

	if ((!data) || (!len))
		return NL_SKIP;

	wpa_hexdump(MSG_MSGDUMP, "nl80211: Vendor data", data, len);

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, (struct nlattr *)data,
	                len, NULL);
	if (ret)
		return NL_SKIP;

	if (tb[MWL_VENDOR_ATTR_SSID])
		*ssid = nla_get_u8(tb[MWL_VENDOR_ATTR_SSID]);

	return NL_SKIP;
}

int marvell_get_ssid(void *priv, u8 *buf, int len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	if (!(msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		        MWL_VENDOR_CMD_GET_SSID)) {
		nlmsg_free(msg);
		return 0;
	}

	ret = send_and_recv_msgs(drv, msg, get_ssid_handler, buf);

	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: err in send_and_recv_msgs", __func__);
		return 0;
	}

	return ret;
}

static int marvell_set_wpawpa2mode(void *priv, u8 wpawpa2mode)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_SET_WPAWPA2MODE) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put_u8(msg, MWL_VENDOR_ATTR_WPAWPA2MODE, wpawpa2mode)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		nlmsg_free(msg);
		return -1;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: %d err in send_and_recv_msgs", __func__, ret);
		return ret;
	}
	nlmsg_free(msg);

	//marvell_commit(priv);

	return ret;
}

static int marvell_set_ciphersuite(void *priv, struct wpa_driver_ap_params *ap_params)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;
	struct nlattr *params;
	u32 wpa_version;
	int max_suites;
	int num_suites;
	int smps_mode;
	u32 suites[10], suite;
	struct mwl_ap_settings *ap_settings;

	ap_settings = os_zalloc(sizeof(struct mwl_ap_settings));
	if (ap_settings == NULL)
		return -1;
	os_memset(ap_settings, 0, sizeof(ap_settings));

	ap_settings->beacon.tail_len =
		(ap_params->tail_len <= 256) ? ap_params->tail_len : 256;
	memcpy(ap_settings->beacon.tail, ap_params->tail, ap_settings->beacon.tail_len);

	ap_settings->ssid_len = (ap_params->ssid_len < 32) ? ap_params->ssid_len : 32;
	memcpy(ap_settings->ssid, ap_params->ssid, ap_settings->ssid_len);

	wpa_version = 0;
	if (ap_params->wpa_version & WPA_PROTO_WPA)
		wpa_version |= NL80211_WPA_VERSION_1;
	if (ap_params->wpa_version & WPA_PROTO_RSN)
		wpa_version |= NL80211_WPA_VERSION_2;
	ap_settings->crypto.wpa_versions = wpa_version;

	num_suites = 0;
	if (ap_params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X)
		suites[num_suites++] = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
	if (ap_params->key_mgmt_suites & WPA_KEY_MGMT_PSK)
		suites[num_suites++] = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;

	ap_settings->crypto.n_akm_suites = num_suites;
	memcpy(ap_settings->crypto.akm_suites, suites, num_suites * sizeof(u32));

	num_suites = 0;
	memset(suites, 0, sizeof(suites));
	max_suites = ARRAY_SIZE(suites);
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_CCMP_256)
		suites[num_suites++] = RSN_CIPHER_SUITE_CCMP_256;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_GCMP_256)
		suites[num_suites++] = RSN_CIPHER_SUITE_GCMP_256;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_CCMP)
		suites[num_suites++] = RSN_CIPHER_SUITE_CCMP;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_GCMP)
		suites[num_suites++] = RSN_CIPHER_SUITE_GCMP;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_TKIP)
		suites[num_suites++] = RSN_CIPHER_SUITE_TKIP;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_WEP104)
		suites[num_suites++] = RSN_CIPHER_SUITE_WEP104;
	if (num_suites < max_suites && ap_params->pairwise_ciphers & WPA_CIPHER_WEP40)
		suites[num_suites++] = RSN_CIPHER_SUITE_WEP40;

	ap_settings->crypto.n_ciphers_pairwise = num_suites;
	memcpy(ap_settings->crypto.ciphers_pairwise, suites, num_suites * sizeof(u32));

	suite = 0;
	switch (ap_params->group_cipher) {
	case WPA_CIPHER_CCMP_256:
		suite = RSN_CIPHER_SUITE_CCMP_256;
		break;
	case WPA_CIPHER_GCMP_256:
		suite = RSN_CIPHER_SUITE_GCMP_256;
		break;
	case WPA_CIPHER_CCMP:
		suite = RSN_CIPHER_SUITE_CCMP;
		break;
	case WPA_CIPHER_GCMP:
		suite = RSN_CIPHER_SUITE_GCMP;
		break;
	case WPA_CIPHER_TKIP:
		suite = RSN_CIPHER_SUITE_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		suite = RSN_CIPHER_SUITE_WEP104;
		break;
	case WPA_CIPHER_WEP40:
		suite = RSN_CIPHER_SUITE_WEP40;
		break;
	case WPA_CIPHER_GTK_NOT_USED:
		suite = RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED;
	}
	ap_settings->crypto.cipher_group = suite;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MRVL_OUI) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			MWL_VENDOR_CMD_CONFIG_WPA) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put(msg, MWL_VENDOR_ATTR_WPA, sizeof(struct mwl_ap_settings), ap_settings)) {
		wpa_printf(MSG_ERROR,
			   "%s: err in adding vendor_cmd and vendor_data",
			   __func__);
		ret = -1;
		goto fail;
	}

	nla_nest_end(msg, params);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);

	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "%s: %d err in send_and_recv_msgs", __func__, ret);
		return ret;
	}

	/* do commit when setting SSID */
	//marvell_commit(priv);
fail:
	os_free(ap_settings);
	nlmsg_free(msg);
	return ret;
}

/*
 * Configure WPA parameters.
 */
int marvell_configure_wpa(void *priv, struct wpa_driver_ap_params *ap_params,
			int beacon_set)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct hostapd_data *hapd = (struct hostapd_data *)(bss->drv->ctx);
	int ret;

	if (hapd->conf->wps_state == 0)
		return 0;

	if (hapd->conf->wps_state == 1) {
		ret = marvell_set_wpawpa2mode(priv, 0x10);
		return ret;
	}

	if (hapd->conf->wps_state == 2) {
		if (beacon_set)
			ret = marvell_set_ciphersuite(priv, ap_params);
		ret = marvell_set_wpawpa2mode(priv, 0x10);
		return ret;
	}
}

