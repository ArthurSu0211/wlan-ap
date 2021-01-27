/*
 * Host AP - driver interface with MARVELL driver
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Copyright (c) 2010-2011, Marvell Semiconductor- added support for Marvell driver glue logics.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
#ifdef HOSTAPD

#include "includes.h"
#include <sys/ioctl.h>

#include <netpacket/packet.h>

#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "l2_packet/l2_packet.h"
#include "common/ieee802_11_defs.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "wireless_copy.h"

#include "ap/hostapd.h"
#include "ap/ap_config.h"

#include "ap8xLnxIoctl.h"
#include "utils/bitfield.h"

#define	IEEE80211_ADDR_LEN	6
#define IE_BUF_LEN            8

struct marvell_driver_data {
	struct hostapd_data *hapd;		/* back pointer */
	char	iface[IFNAMSIZ + 1];
	char	master_iface[IFNAMSIZ + 1];
	int     ifindex;
	int	master_ifindex;
	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
	struct l2_packet_data *sock_recv;	/* raw packet recv socket */
#ifdef CONFIG_IEEE80211R
	struct l2_packet_data *sock_tx_rrb;
	struct l2_packet_data *sock_rx_rrb;
#endif
	int	ioctl_sock;			/* socket for ioctl() use */
	struct netlink_data *netlink;
	int	we_version;
	u8	acct_mac[ETH_ALEN];
	struct hostap_sta_driver_data acct_data;
	struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
};

static int marvell_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, int reason_code);

static int marvell_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code);

#ifdef CONFIG_IEEE80211R
static int marvell_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr, int reassoc, u16 status_code, const u8 *ie, size_t len); //Pete
#endif

static int
marvell_commit (void *priv);

static int
set80211priv(struct marvell_driver_data *drv, int op, void *data, int len) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
		return -1;
	}

	return 0;
}

static int
get80211priv(struct marvell_driver_data *drv, int op, void *data, int len) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
		return -1;
	}

	if (len < IFNAMSIZ)
		memcpy(data, iwr.u.name, len);
	return iwr.u.data.length;
}

static int
set80211param(struct marvell_driver_data *drv, int op, int arg, Boolean commit) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = op;
	memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

	if (ioctl(drv->ioctl_sock, WL_IOCTL_WL_PARAM, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_WL_PARAM]");
		return -1;
	}

	if (commit) {
		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
		if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
			printf("ioctl[SIOCSIWCOMMIT]");
			return -1;
		}
	}
	return 0;
}

static int
get80211param(struct marvell_driver_data *drv, int op, void *value) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = op;
	//memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

	if (ioctl(drv->ioctl_sock, WL_IOCTL_WL_GET_PARAM, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_WL_GET_PARAM]");
		return -1;
	}
	if (sizeof(int) < IFNAMSIZ)
		memcpy(value, iwr.u.name, sizeof(iwr.u));
	return 0;
}

static const char *
ether_sprintf(const u8 *addr) {
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}


/*
 * Configure WPA parameters.
 */
static int
marvell_configure_wpa(struct marvell_driver_data *drv, struct wpa_bss_params *params) {
	u8 wpawpa2mode;
	char ciphersuite[24];

	/* In WPS mode, set the WPAWPA2MODE to 0x13 (extended mixed mode)
	* with the exception of WPA2PSK-TKIP. For WPA2PSK-TKIP set the
	* the WPAWPA2MODE as 0x12 (extended WPA2PSK mode).
	*/
	if (drv->hapd->conf->wps_state) {
		// Set wpawpa2mode if WPA2PSK-TKIP
		if ((params->wpa & WPA_PROTO_RSN) &&
				!(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK) &&
				((params->wpa_pairwise & WPA_CIPHER_CCMP) ||
				 (params->wpa_pairwise & WPA_CIPHER_TKIP))) {
			wpawpa2mode = 0x12;
		}
		// Set wpawpa2mode if WPAPSK-TKIP
		else if (!(params->wpa & WPA_PROTO_RSN) &&
				(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK) &&
				((params->wpa_pairwise & WPA_CIPHER_CCMP) ||
				 (params->wpa_pairwise & WPA_CIPHER_TKIP))) {
			wpawpa2mode = 0x11;
		} else {
			wpawpa2mode = 0x13; // WSC custom mixed mode
		}

		if (set80211param(drv, WL_PARAM_WPAWPA2MODE, wpawpa2mode,TRUE)) {
			wpa_printf(MSG_DEBUG,"%s: WPS Extended mode %x setting failed", __func__,wpawpa2mode);
			return -1;
		}

		// Set ciphersuite if WPA2PSK-TKIP
		if ((params->wpa & WPA_PROTO_RSN) &&
				!(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK) &&
				!(params->wpa_pairwise & WPA_CIPHER_CCMP) &&
				(params->wpa_pairwise & WPA_CIPHER_TKIP)) {
			strcpy(ciphersuite, "wpa2 tkip");

			/* Set ciphersuite and commit */
			if (set80211priv(drv, WL_IOCTL_SET_CIPHERSUITE,
					 &ciphersuite, sizeof(ciphersuite))) {
				wpa_printf(MSG_DEBUG,"%s: Cipher Suite %s setting failed", __func__,ciphersuite);
				return -1;
			}
		}
		// Set ciphersuite if WPAPSK-AES
		else if (!(params->wpa & WPA_PROTO_RSN) &&
				(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK) &&
				(params->wpa_pairwise & WPA_CIPHER_CCMP) &&
				!(params->wpa_pairwise & WPA_CIPHER_TKIP)) {
			strcpy(ciphersuite, "wpa aes-ccmp");

			/* Set ciphersuite and commit */
			if (set80211priv(drv, WL_IOCTL_SET_CIPHERSUITE,
					 &ciphersuite, sizeof(ciphersuite))) {
				wpa_printf(MSG_DEBUG,"%s: WPS Cipher Suite %s setting failed", __func__,ciphersuite);
				return -1;
			}
		}
	} else {
		if ((params->wpa & WPA_PROTO_WPA) &&
				!(params->wpa & WPA_PROTO_RSN) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK))
			wpawpa2mode = 0x81;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				!(params->wpa & WPA_PROTO_WPA) &&
				((params->wpa_key_mgmt & WPA_KEY_MGMT_PSK) ||
				 (params->wpa_key_mgmt & WPA_KEY_MGMT_PSK_SHA256)||
				 (params->wpa_key_mgmt & WPA_KEY_MGMT_FT_PSK)))
			wpawpa2mode = 0x82;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_PSK))
			wpawpa2mode = 0x83;
		else if ((params->wpa & WPA_PROTO_WPA) &&
				!(params->wpa & WPA_PROTO_RSN) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X))
			wpawpa2mode = 0x84;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				!(params->wpa & WPA_PROTO_WPA) &&
        		((params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X)||
        		(params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256)))
			wpawpa2mode = 0x85;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				(params->wpa & WPA_PROTO_WPA) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X))
			wpawpa2mode = 0x86;
        else if ((params->wpa & WPA_PROTO_RSN) &&
                (params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B))
                wpawpa2mode = 0x87;
        else if ((params->wpa & WPA_PROTO_RSN) &&
                (params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192))
                wpawpa2mode = 0x88;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_SAE))
				wpawpa2mode = 0x89;
		else if ((params->wpa & WPA_PROTO_RSN) &&
				(params->wpa_key_mgmt & WPA_KEY_MGMT_OWE))
				wpawpa2mode = 0x8a;
		else
			wpawpa2mode = 0;

		if (params->wpa & WPA_PROTO_RSN) {
			if (drv->hapd->conf->ieee80211w) {
				wpawpa2mode |= 0x20;
				wpa_printf(MSG_DEBUG,"%s: ieee80211w Mode %d", __func__, drv->hapd->conf->ieee80211w);
			}
			if ((params->wpa_key_mgmt & WPA_KEY_MGMT_PSK_SHA256) || (params->wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256))
				wpawpa2mode |= 0x40;
		}

		if (set80211param(drv, WL_PARAM_WPAWPA2MODE, wpawpa2mode,TRUE)) {
			wpa_printf(MSG_DEBUG,"%s: Mode %x setting failed", __func__,wpawpa2mode);
			return -1;
		}
	}

	if ((params->wpa & WPA_PROTO_WPA) &&
			(params->wpa_pairwise & WPA_CIPHER_TKIP))
		strcpy(ciphersuite, "wpa tkip");
	else if ((params->wpa & WPA_PROTO_RSN) &&
			(params->wpa_pairwise & WPA_CIPHER_CCMP))
		strcpy(ciphersuite, "wpa2 aes-ccmp");
	else if ((params->wpa & WPA_PROTO_RSN) &&
			(params->wpa_pairwise & WPA_CIPHER_GCMP))
		strcpy(ciphersuite, "wpa2 aes-gcmp");
	else if ((params->wpa & WPA_PROTO_RSN) &&
			(params->wpa_pairwise & WPA_CIPHER_CCMP_256))
		strcpy(ciphersuite, "wpa2 aes-ccmp-256");
	else if ((params->wpa & WPA_PROTO_RSN) &&
			(params->wpa_pairwise & WPA_CIPHER_GCMP_256))
		strcpy(ciphersuite, "wpa2 aes-gcmp-256");
	else if ((params->wpa & WPA_PROTO_RSN) &&
			(params->wpa_pairwise & WPA_CIPHER_TKIP))
		strcpy(ciphersuite, "wpa2 tkip");
	else if ((params->wpa & WPA_PROTO_WPA) &&
			(params->wpa_pairwise & WPA_CIPHER_CCMP))
		strcpy(ciphersuite, "wpa aes-ccmp");

	if (set80211priv(drv, WL_IOCTL_SET_CIPHERSUITE, &ciphersuite, sizeof(ciphersuite))) {
		wpa_printf(MSG_DEBUG,"%s: Cipher Suite %s setting failed", __func__,ciphersuite);
		return -1;
	}

	wpa_printf(MSG_DEBUG,"%s:configured mode=%x cipher suite=%s", __func__,wpawpa2mode,ciphersuite);

	return 0;
}

static int
marvell_set_ieee8021x(void *priv, struct wpa_bss_params *params) {
	struct marvell_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG,"%s: enabled=%d", __func__, params->enabled);

	if (!params->enabled) {
		if (drv->hapd->conf->wps_state)
			return set80211param(priv, WL_PARAM_WPAWPA2MODE, 0x10, TRUE);
		else
			return set80211param(priv, WL_PARAM_WPAWPA2MODE, 0, TRUE);
	}

	if (!params->wpa && !params->ieee802_1x) {
		hostapd_logger(drv->hapd, NULL, HOSTAPD_MODULE_DRIVER,
			       HOSTAPD_LEVEL_WARNING, "No 802.1X or WPA enabled!");
		return -1;
	}

	if (params->wpa && marvell_configure_wpa(drv, params) != 0) {
		hostapd_logger(drv->hapd, NULL, HOSTAPD_MODULE_DRIVER,
			       HOSTAPD_LEVEL_WARNING, "Error configuring WPA state!");
		return -1;
	}

	if (drv->hapd->conf->wps_state && !params->wpa) {
		/* WPS Extended Open mode setting - WPAWPA2MODE - 0x10 */
		if ( set80211param(drv, WL_PARAM_WPAWPA2MODE, 0x10,TRUE) ) {
			wpa_printf(MSG_DEBUG,"%s: WPS Extended Open mode setting failed\n", __func__);
			return -1;
		}
	}

	return 0;
}


static int
marvell_del_key(void *priv, const u8 *addr, int key_idx) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_del_key wk;
	int ret;

	wpa_printf(MSG_DEBUG,"%s: addr=%s key_idx=%d",
		   __func__, ether_sprintf(addr), key_idx);

	memset(&wk, 0, sizeof(wk));
	if (addr != NULL) {
		memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (u8) WL_KEYIX_NONE;
	} else {
		wk.idk_keyix = key_idx;
	}
	ret = set80211param(drv, WL_PARAM_DELKEYS, (int)&wk,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to delete key (addr %s"
			   " key_idx %d)", __func__, ether_sprintf(addr),
			   key_idx);
	}

	return ret;
}

static int
marvell_set_key(const char *ifname,void *priv, enum wpa_alg alg,
		const u8 *addr, int key_idx, int set_tx, const u8 *seq,
		size_t seq_len, const u8 *key, size_t key_len) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_key wk;
	u_int8_t cipher;
	int ret;

	if (alg == WPA_ALG_NONE)
		return marvell_del_key(priv, addr, key_idx);

	wpa_printf(MSG_DEBUG,
		   "%s: alg=%d addr=%s key_idx=%d\n",
		   __func__, alg, ether_sprintf(addr), key_idx);

	switch (alg) {
	case WPA_ALG_WEP:
		cipher = WL_CIPHER_WEP104;
		break;
	case WPA_ALG_TKIP:
		cipher = WL_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		cipher = WL_CIPHER_CCMP;
		break;
	case WPA_ALG_IGTK:
		cipher = WL_CIPHER_IGTK;
		break;
	case WPA_ALG_CCMP_256:
		cipher = WL_CIPHER_CCMP_256;
		break;
	case WPA_ALG_GCMP:
		cipher = WL_CIPHER_GCMP;
		break;
	case WPA_ALG_GCMP_256:
		cipher = WL_CIPHER_GCMP_256;
		break;
	case WPA_ALG_BIP_CMAC_256:
		cipher = WL_CIPHER_AES_CMAC_256;
		break;
	case WPA_ALG_BIP_GMAC_128:
		cipher = WL_CIPHER_AES_GMAC;
		break;
	case WPA_ALG_BIP_GMAC_256:
		cipher = WL_CIPHER_AES_GMAC_256;
		break;
	default:
		printf("%s: unknown/unsupported algorithm %d\n",
		       __func__, alg);
		return -1;
	}

	if (key_len > sizeof(wk.ik_keydata)) {
		printf("%s: key length %lu too big\n", __func__,
		       (unsigned long) key_len);
		return -3;
	}

	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = WL_KEY_RECV | WL_KEY_XMIT;
	if (addr == NULL || is_broadcast_ether_addr(addr)) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = key_idx;
		wk.ik_flags |= WL_KEY_DEFAULT;
	} else {
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = WL_KEYIX_NONE;
	}
	wk.ik_keylen = key_len;
	memcpy(wk.ik_keydata, key, key_len);
	memcpy(wk.ik_pn, seq, seq_len);
	memcpy(&wk.ik_keytsc, seq, seq_len);

	ret = set80211param(drv, WL_PARAM_SETKEYS, (int)&wk,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to set key (addr %s"
			   " key_idx %d alg '%d' key_len %lu txkey %d)",
			   __func__, ether_sprintf(wk.ik_macaddr), key_idx,
			   alg, (unsigned long) key_len, set_tx);
	}

	return ret;
}

static int
marvell_flush(void *priv) {
	u8 allsta[IEEE80211_ADDR_LEN];
	memset(allsta, 0xff, IEEE80211_ADDR_LEN);
	return marvell_sta_deauth(priv, NULL, allsta, 3); /*IEEEtypes_REASON_DEAUTH_LEAVING*/
}


static int
marvell_read_sta_driver_data(void *priv, struct hostap_sta_driver_data *data,
			     const u8 *addr) {
	return 0;
}

static int
marvell_set_opt_ie(void *priv, const u8 *ie, size_t ie_len) {
#ifdef CONFIG_IEEE80211R
	u8 buf[512];
	struct wlreq_set_appie * app_ie;

	app_ie = (struct wlreq_set_appie *)buf;
	app_ie->appBufLen = ie_len;

	if (ie != NULL && ie_len != 0) {
		memcpy(&(app_ie->appBuf[0]), ie , ie_len);
	} else {
		memset(&(app_ie->appBuf[0]), 0x00, IE_BUF_LEN);
		app_ie->appBufLen = IE_BUF_LEN;
	}
	app_ie->appFrmType = WL_OPTIE_BEACON_INCL_RSN;
	set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
		     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) + app_ie->appBufLen);
	app_ie->appFrmType = WL_OPTIE_PROBE_RESP_INCL_RSN;
	set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
		     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) + app_ie->appBufLen);
#endif
	return 0;
}

static int
marvell_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, int reason_code) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_mlme mlme;

	wpa_printf(MSG_DEBUG,
		   "%s: addr=%s reason_code=%d\n",
		   __func__, ether_sprintf(addr), reason_code);

	mlme.im_op = WL_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);

	return set80211param(drv, WL_PARAM_MLME_REQ, (int)&mlme,FALSE);
}

static int
marvell_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_mlme mlme;

	wpa_printf(MSG_DEBUG,
		   "%s: addr=%s reason_code=%d\n",
		   __func__, ether_sprintf(addr), reason_code);

	mlme.im_op = WL_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);

	return set80211param(drv, WL_PARAM_MLME_REQ, (int)&mlme,FALSE);
}

#ifdef CONFIG_IEEE80211R
static int
marvell_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
		  int reassoc, u16 status_code, const u8 *ie, size_t len) 
{
	struct marvell_driver_data *drv = priv;
	struct wlreq_mlme mlme;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d reassoc %d",
		   __func__, ether_sprintf(addr), status_code, reassoc);

	if (reassoc)
		mlme.im_op = WL_MLME_SET_REASSOC;
	else
		mlme.im_op = WL_MLME_SET_ASSOC;
	mlme.im_reason = status_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	mlme.im_optie_len = len;
	if (len) {
		//if (len < IEEE80211_MAX_OPT_IE) {
		if (len < 256) {
			os_memcpy(mlme.im_optie, ie, len);
		} else {
			wpa_printf(MSG_DEBUG, "%s: Not enough space to copy "
				   "opt_ie STA (addr " MACSTR " reason %d, "
				   "ie_len %d)",
				   __func__, MAC2STR(addr), status_code,
				   (int) len);
			return -1;
		}
	}
	ret = set80211param(drv, WL_PARAM_MLME_REQ, (int)&mlme,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to assoc STA (addr " MACSTR
			   " reason %d)",
			   __func__, MAC2STR(addr), status_code);
	}
	return ret;
}

static int
marvell_sta_auth(void *priv, 
        struct wpa_driver_sta_auth_params *param) 
{
	struct marvell_driver_data *drv = priv;
	struct wlreq_mlme mlme;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: addr=%s status_code=%d",
		   __func__, ether_sprintf(param->addr), param->status);

	mlme.im_op = WL_MLME_SET_AUTH;
	mlme.im_reason = param->status;
	mlme.im_seq = param-> seq;
	os_memcpy(mlme.im_macaddr, param->addr, IEEE80211_ADDR_LEN);
	mlme.im_optie_len = param->len;
	if (param->len) {
		if (param->len < 256) {
			os_memcpy(mlme.im_optie, param->ie, param->len);
		} else {
			return -1;
		}
	}
	ret = set80211param(drv, WL_PARAM_MLME_REQ, (int)&mlme,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to auth STA (addr " MACSTR
			   " reason %d)",
			   __func__, MAC2STR(param->addr), param->status);
	}
	return ret;
}
#endif

#ifdef CONFIG_WPS
static void marvell_raw_recv_wps(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	/* Send Probe Request information to WPS processing */
	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ)
		return;

	os_memset(&event, 0, sizeof(event));
	event.rx_probe_req.sa = mgmt->sa;
	event.rx_probe_req.da = mgmt->da;
	event.rx_probe_req.bssid = mgmt->bssid;
	event.rx_probe_req.ie = mgmt->u.probe_req.variable;
	event.rx_probe_req.ie_len =
		len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
	wpa_supplicant_event(drv->hapd, EVENT_RX_PROBE_REQ, &event);
}
#endif /* CONFIG_WPS */

#ifdef MRVL_BANDSTEER
static void marvell_raw_recv_mgmt(void *ctx, const u8 *src_addr, const u8 *buf,
				  size_t len, int rssi) {
	struct marvell_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	/* Send the Probe Request or Authenticate frame for Band Steering processing */
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			(WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ &&
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_AUTH))
		return;

	//if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_REQ)
	//	wpa_printf(MSG_INFO, "%s: Received Probe Request frame", __func__);
	//if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH)
	//	wpa_printf(MSG_INFO, "%s: Received Authenticate frame", __func__);

	os_memset(&event, 0, sizeof(event));
	event.rx_mgmt.frame = (const u8 *) mgmt;
	event.rx_mgmt.frame_len = len;
	event.rx_mgmt.ssi_signal = rssi;
	wpa_supplicant_event(drv->hapd, EVENT_RX_MGMT, &event);
}
#endif

static void marvell_raw_recv_mgmt_wpa3(void *ctx, const u8 *src_addr, const u8 *buf,
				  size_t len, int rssi) {
	struct marvell_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			(WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_AUTH &&
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ASSOC_REQ))
		return;

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH)
		wpa_printf(MSG_INFO, "%s: Received Authenticate frame", __func__);

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ASSOC_REQ)
		wpa_printf(MSG_INFO, "%s: Received Associate Req frame", __func__);

	os_memset(&event, 0, sizeof(event));
	event.rx_mgmt.frame = (const u8 *) mgmt;
	event.rx_mgmt.frame_len = len;
	event.rx_mgmt.ssi_signal = rssi;
	wpa_supplicant_event(drv->hapd, EVENT_RX_MGMT, &event);
}


#ifdef CONFIG_HS20
static void marvell_raw_recv_hs20(void *ctx, const u8 *src_addr, const u8 *buf,
				  size_t len) {
	struct marvell_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	/* Send the Action frame for HS20 processing */

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.action.category) +
			sizeof(mgmt->u.action.u.public_action))
		return;

	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ACTION ||
			mgmt->u.action.category != WLAN_ACTION_PUBLIC)
		return;

	wpa_printf(MSG_DEBUG, "%s:Received Public Action frame", __func__);

	os_memset(&event, 0, sizeof(event));
	event.rx_mgmt.frame = (const u8 *) mgmt;
	event.rx_mgmt.frame_len = len;
	wpa_supplicant_event(drv->hapd, EVENT_RX_MGMT, &event);
}
#endif /* CONFIG_HS20 */

#if defined(CONFIG_WNM)
static void marvell_raw_recv_11v(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	union wpa_event_data event;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	u16 stype;

	/* Do 11R processing for WNM ACTION frames */
	if (len < IEEE80211_HDRLEN)
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: subtype 0x%x len %d", __func__, stype,
		   (int) len);

	/*
		if (os_memcmp(drv->own_addr, mgmt->bssid, ETH_ALEN) != 0) {
	    		wpa_printf(MSG_DEBUG, "%s: BSSID does not match - ignore",
	          			 __func__);
	    		return;
			}
		*/

	switch (stype) {
	case WLAN_FC_STYPE_ACTION:
		if (&mgmt->u.action.category > buf + len)
			break;
		os_memset(&event, 0, sizeof(event));
		event.rx_action.da = mgmt->da;
		event.rx_action.sa = mgmt->sa;
		event.rx_action.bssid = mgmt->bssid;
		event.rx_action.category = mgmt->u.action.category;
		event.rx_action.data = &mgmt->u.action.category;
		event.rx_action.len = buf + len - event.rx_action.data;
		wpa_supplicant_event(drv->hapd, EVENT_RX_ACTION, &event);
		break;
	default:
		break;
	}
}
#endif /* CONFIG_WNM */

#ifdef CONFIG_IEEE80211R
static void marvell_raw_recv_11r(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	union wpa_event_data event;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	u16 stype;

	if (len < IEEE80211_HDRLEN)
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: subtype 0x%x len %d", __func__, stype, (int) len);
	os_memset(&event, 0, sizeof(event));
	switch (stype) {
	case WLAN_FC_STYPE_ACTION:
		if (&mgmt->u.action.category > buf + len)
			break;
		if ((mgmt->u.action.category == WLAN_ACTION_FT) || (mgmt->u.action.category == WLAN_ACTION_PUBLIC)
				|| (mgmt->u.action.category == WLAN_ACTION_PROTECTED_DUAL)) {
			os_memset(&event, 0, sizeof(event));
			event.rx_action.da = mgmt->da;
			event.rx_action.sa = mgmt->sa;
			event.rx_action.bssid = mgmt->bssid;
			event.rx_action.category = mgmt->u.action.category;
			event.rx_action.data = &mgmt->u.action.category;
			event.rx_action.len = buf + len - event.rx_action.data;
			event.rx_mgmt.frame = buf;
			event.rx_mgmt.frame_len = len;
			event.rx_mgmt.drv_priv = (void *)drv;
			wpa_supplicant_event(drv->hapd, EVENT_RX_MGMT, &event);
		} else
			printf("Not FT Action ...\n");
		break;
	case WLAN_FC_STYPE_AUTH:
		if (len - IEEE80211_HDRLEN < sizeof(mgmt->u.auth))
			break;
		os_memset(&event, 0, sizeof(event));
		os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
		os_memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
		event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
		event.auth.auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
		event.auth.status_code = le_to_host16(mgmt->u.auth.status_code);
		event.auth.ies = mgmt->u.auth.variable;
		event.auth.ies_len = len - IEEE80211_HDRLEN -sizeof(mgmt->u.auth);
		wpa_supplicant_event(drv->hapd, EVENT_AUTH, &event);
		break;

	default:
		break;
	}
}
#endif /* CONFIG_WNM */

#if defined(CONFIG_WPS) || defined(CONFIG_WNM) || defined(CONFIG_HS20) || defined(CONFIG_IEEE80211R)
static void marvell_raw_receive(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len) {
#ifdef CONFIG_WPS
	marvell_raw_recv_wps(ctx, src_addr, buf, len);
#endif /* CONFIG_WPS */
#if defined(CONFIG_WNM)
	//marvell_raw_recv_11v(ctx, src_addr, buf, len);
#endif /* CONFIG_WNM */
#ifdef CONFIG_HS20
	marvell_raw_recv_hs20(ctx, src_addr, buf, len);
#endif /* CONFIG_HS20 */
#ifdef CONFIG_IEEE80211R
	marvell_raw_recv_11r(ctx, src_addr, buf, len);
#endif
}
#endif /* CONFIG_WPS || CONFIG_WNM || CONFIG_HS20 */


static int
marvell_set_wsc_ie(void *priv, const u8 *iebuf, int iebuflen, u32 frametype) {
	u8 buf[512];
	struct wlreq_set_appie * app_ie;

	wpa_printf(MSG_DEBUG, "%s buflen = %d", __func__, iebuflen);

	app_ie = (struct wlreq_set_appie *)buf;
	app_ie->appFrmType = frametype;
	app_ie->appBufLen = iebuflen;

	if (iebuf != NULL)
		memcpy(&(app_ie->appBuf[0]), iebuf , iebuflen );
	else {
		memset(&(app_ie->appBuf[0]),0x00, IE_BUF_LEN);
		app_ie->appBufLen = IE_BUF_LEN;
	}

	return set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
			    sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) + app_ie->appBufLen);

}

static int
marvell_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
		      const struct wpabuf *proberesp,const struct wpabuf *assocresp) {
	if (marvell_set_wsc_ie(priv, beacon ? wpabuf_head(beacon) : NULL,
			       beacon ? wpabuf_len(beacon) : 0,
			       WL_APPIE_FRAMETYPE_BEACON))
		return -1;

	return marvell_set_wsc_ie(priv,
				  proberesp ? wpabuf_head(proberesp) : NULL,
				  proberesp ? wpabuf_len(proberesp): 0,
				  WL_APPIE_FRAMETYPE_PROBE_RESP);
}

static int
marvell_set_rsn(const char *ifname,void *priv, enum wpa_alg alg,
		const u8 *addr, int key_idx, int set_tx, const u8 *seq,
		size_t seq_len, const u8 *key, size_t key_len) {
	struct marvell_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	u8 buf[280];
	struct wlreq_set_appie * app_ie;


	app_ie = (struct wlreq_set_appie *)buf;
	if (hapd->conf->osen)
		app_ie->appFrmType = 49;    //OSEN
	else
		app_ie->appFrmType = 48;    //RSN
	app_ie->appBufLen = key_len;

	if (key != NULL)
		memcpy(&(app_ie->appBuf[0]), key , key_len );
	else
		return 0;

	return set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
			    sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) + key_len);

}


static int
marvell_new_sta(struct marvell_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN]) {
	struct wlreq_ie ie;
	struct hostapd_data *hapd = drv->hapd;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "associated");

	/* Get RSN IE */
	memset(&ie, 0, sizeof(ie));
	memcpy(ie.macAddr, addr, 6);
	ie.IEtype = WLAN_EID_RSN;

	if (get80211priv(drv, WL_IOCTL_GET_IE, &ie, sizeof(ie))<0) {
		wpa_printf(MSG_DEBUG,"%s: IOCTL Get IE failed\n", __func__);
		return -1;
	}

	if (ie.IELen == 0) {
		wpa_printf(MSG_DEBUG,"%s: STA addr %s RSN IE Length is zero\n", __func__, ether_sprintf(addr));
	}

	drv_event_assoc(hapd, addr, ie.IE, ie.IELen, ie.reassoc);

	if (memcmp(addr, drv->acct_mac, ETH_ALEN) == 0) {
		/* Cached accounting data is not valid anymore. */
		memset(drv->acct_mac, 0, ETH_ALEN);
		memset(&drv->acct_data, 0, sizeof(drv->acct_data));
	}

	return 0;
}

static void
marvell_wireless_event_wireless_custom(struct marvell_driver_data *drv,
				       char *custom, uint16_t rssi) {
	//wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		char *pos;
		u8 addr[ETH_ALEN];
		pos = strstr(custom, "addr=");
		if (pos == NULL) {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "without sender address ignored");
			return;
		}
		pos += 5;
		if (hwaddr_aton(pos, addr) == 0) {
			union wpa_event_data data;
			os_memset(&data, 0, sizeof(data));
			data.michael_mic_failure.unicast = 1;
			data.michael_mic_failure.src = NULL;
			wpa_supplicant_event(drv->hapd,
					     EVENT_MICHAEL_MIC_FAILURE, &data);
		} else {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "with invalid MAC address");
		}
	} else if (strncmp(custom, "STA-TRAFFIC-STAT", 16) == 0) {
		char *key, *value;
		u32 val;
		key = custom;
		while ((key = strchr(key, '\n')) != NULL) {
			key++;
			value = strchr(key, '=');
			if (value == NULL)
				continue;
			*value++ = '\0';
			val = strtoul(value, NULL, 10);
			if (strcmp(key, "mac") == 0)
				hwaddr_aton(value, drv->acct_mac);
			else if (strcmp(key, "rx_packets") == 0)
				drv->acct_data.rx_packets = val;
			else if (strcmp(key, "tx_packets") == 0)
				drv->acct_data.tx_packets = val;
			else if (strcmp(key, "rx_bytes") == 0)
				drv->acct_data.rx_bytes = val;
			else if (strcmp(key, "tx_bytes") == 0)
				drv->acct_data.tx_bytes = val;
			key = value;
		}
	} else if (strncmp(custom, "mlme-probe_request", strlen("mlme-probe_request")) == 0) {
#define MLME_FRAME_TAG_SIZE  20
#ifdef MRVL_WPS2
		s16 len = WPA_GET_LE16(custom + strlen("mlme-probe_request"));
#else
		s16 len = *(custom + 18);
#endif
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-probe_request "
				   "length %d", len);
			return;
		}

		marvell_raw_receive(drv, NULL, (u8 *) custom + MLME_FRAME_TAG_SIZE, len);
	}
#ifdef MRVL_BANDSTEER
	else if (strncmp(custom, "raw-mlme-probe_request", strlen("raw-mlme-probe_request")) == 0) {
		s16 len = WPA_GET_LE16(custom + strlen("raw-mlme-probe_request"));
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "raw-mlme-probe_request length %d", len);
			return;
		}
		marvell_raw_recv_mgmt(drv, NULL, (u8 *) custom + strlen("raw-mlme-probe_request")+2, len, rssi);
	} else if (strncmp(custom, "raw-mlme-authenticate", strlen("raw-mlme-authenticate")) == 0) {
		s16 len = WPA_GET_LE16(custom + strlen("raw-mlme-authenticate"));
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "raw-mlme-authenticate length %d", len);
			return;
		}
		marvell_raw_recv_mgmt(drv, NULL, (u8 *) custom + strlen("raw-mlme-authenticate")+2, len, rssi);
	}
#endif
	else if (strncmp(custom, "drv_mgmtrx", strlen("drv_mgmtrx")) == 0) {
		s16 len = WPA_GET_LE16(custom + strlen("drv_mgmtrx"));
		wpa_printf(MSG_DEBUG, "drv_mgmtrx length %d", len);
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "drv_mgmtrx length %d", len);
			return;
		}
		marvell_raw_recv_mgmt_wpa3(drv, NULL, (u8 *) custom + strlen("drv_mgmtrx")+2, len, rssi);
	}
#ifdef CONFIG_IEEE80211R
	else if (strncmp(custom, "mlme-action", strlen("mlme-action")) == 0) {
		s16 len = WPA_GET_LE16(custom + strlen("mlme-action"));
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-action"
				   "length %d", len);
			return;
		}
		marvell_raw_receive(drv, NULL, (u8 *) custom + strlen("mlme-action")+2, len);
	} else if (strncmp(custom, "mlme-auth", strlen("mlme-auth")) == 0) {
		s16 len = WPA_GET_LE16(custom+strlen("mlme-auth"));
		printf("mlme-auth length=%d\n", len);
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-auth"
				   "length %d", len);
			return;
		}
		marvell_raw_receive(drv, NULL, (u8 *) custom+strlen("mlme-auth")+2, len);
	}
#endif
	else if (strstr(custom, "Unexpected event - External recovery recommended: ") != NULL) {
		printf("received recovery event rebooting\n");
		system("reboot");
	}
}

static void
marvell_wireless_event_wireless(struct marvell_driver_data *drv,
				char *data, int len) {
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
//		wpa_printf(MSG_MSGDUMP, "Wireless event: cmd=0x%x len=%d", iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
				(iwe->cmd == IWEVMICHAELMICFAILURE ||
				 iwe->cmd == IWEVASSOCREQIE ||
				 iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case IWEVEXPIRED:
			drv_event_disassoc(drv->hapd,
					   (u8 *) iwe->u.addr.sa_data);
			break;
		case IWEVREGISTERED:
			/* First reset the station state so that if the station did not
			* send explicit deauth, it will still be ok.
			*/
			//drv_event_disassoc(drv->hapd, (u8 *) iwe->u.addr.sa_data);
			marvell_new_sta(drv, (u8 *) iwe->u.addr.sa_data);
			break;
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;		/* XXX */
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			marvell_wireless_event_wireless_custom(drv, buf, iwe->u.data.flags);
			free(buf);
			break;
		}

		pos += iwe->len;
	}
}
static void
marvell_wireless_event_rtm_newlink(void *ctx,
				   struct ifinfomsg *ifi, u8 *buf, size_t len) {
	struct marvell_driver_data *drv = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;

	if ((ifi->ifi_index != drv->ifindex) && (ifi->ifi_index != drv->master_ifindex))
		return;
	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			marvell_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}

static int
marvell_get_we_version(struct marvell_driver_data *drv) {
	struct iw_range *range;
	struct iwreq iwr;
	int minlen;
	size_t buflen;

	drv->we_version = 0;

	/*
	 * Use larger buffer than struct iw_range in order to allow the
	 * structure to grow in the future.
	 */
	buflen = sizeof(struct iw_range) + 500;
	range = os_zalloc(buflen);
	if (range == NULL)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) range;
	iwr.u.data.length = buflen;

	minlen = ((char *) &range->enc_capa) - (char *) range +
		 sizeof(range->enc_capa);

	if (ioctl(drv->ioctl_sock, SIOCGIWRANGE, &iwr) < 0) {
		perror("ioctl[SIOCGIWRANGE]");
		free(range);
		return -1;
	} else if (iwr.u.data.length >= minlen &&
			range->we_version_compiled >= 18) {
		wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
			   "WE(source)=%d enc_capa=0x%x",
			   range->we_version_compiled,
			   range->we_version_source,
			   range->enc_capa);
		drv->we_version = range->we_version_compiled;
	}

	free(range);
	return 0;
}


static int
marvell_wireless_event_init(struct marvell_driver_data *drv) {
	struct netlink_config *cfg;

	marvell_get_we_version(drv);

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = drv;
	cfg->newlink_cb = marvell_wireless_event_rtm_newlink;
	drv->netlink = netlink_init(cfg);
	if (drv->netlink == NULL) {
		os_free(cfg);
		return -1;
	}

	return 0;
}

static int
marvell_send_ether(void *priv, const u8 *dst, const u8 *src, u16 proto, const u8 *data, size_t data_len) {
	struct marvell_driver_data *drv = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	/*
	 * Prepend the Ethernet header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
			       "buffer of size %lu!\n", (unsigned long) len);
			return -1;
		}
	}
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, dst, ETH_ALEN);
	memcpy(eth->h_source, src, ETH_ALEN);
	eth->h_proto = htons(proto);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX Ether", bp, len);

#ifdef CONFIG_IEEE80211R
	status = l2_packet_send(drv->sock_tx_rrb, dst, proto, bp, len);
#else
	status = l2_packet_send(drv->sock_xmit, dst, proto, bp, len);
#endif

	if (bp != buf)
		free(bp);
	return status;
}

static int
marvell_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
		   int encrypt, const u8 *own_addr) {
	struct marvell_driver_data *drv = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	/*
	 * Prepend the Ethernet header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
			       "buffer of size %lu!\n", (unsigned long) len);
			return -1;
		}
	}
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, addr, ETH_ALEN);
	memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = host_to_be16(ETH_P_EAPOL);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	status = l2_packet_send(drv->sock_xmit, addr, ETH_P_EAPOL, bp, len);

	if (bp != buf)
		free(bp);
	return status;
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len) {
	struct marvell_driver_data *drv = ctx;
	drv_event_eapol_rx(drv->hapd, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}

#ifdef CONFIG_IEEE80211R
static void hostapd_rrb_receive(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len) {
	struct marvell_driver_data *drv = ctx;
	struct l2_ethhdr *ethhdr;
	if (len < sizeof(*ethhdr))
		return;
	ethhdr = (struct l2_ethhdr *) buf;
	wpa_printf(MSG_DEBUG, "FT: RRB received packet " MACSTR " -> "
		   MACSTR, MAC2STR(ethhdr->h_source), MAC2STR(ethhdr->h_dest));
	wpa_ft_rrb_rx(drv->hapd->wpa_auth, ethhdr->h_source, buf + sizeof(*ethhdr),
		      len - sizeof(*ethhdr));
}
#endif

static struct bitfield *capa_bits;
static struct bitfield *marvell_ext_capa_mask;
static struct bitfiled *per_capa_bits;

static void *
marvell_init(struct hostapd_data *hapd, struct wpa_init_params *params) {
	struct marvell_driver_data *drv;
	struct ifreq ifr;
	char brname[IFNAMSIZ];

	wpa_printf(MSG_DEBUG, "%s\n", __FUNCTION__);
	/*allocate bitfields for ext capabilities */
	capa_bits = bitfield_alloc(10*8);
	per_capa_bits = bitfield_alloc(10*8);
	marvell_ext_capa_mask = bitfield_alloc(10*8);
	bitfield_set(per_capa_bits, 14);
	bitfield_set(per_capa_bits, 15);
	bitfield_set(per_capa_bits, 31);
	bitfield_set(per_capa_bits, 70);

	drv = os_zalloc(sizeof(struct marvell_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for marvell driver data\n");
		return NULL;
	}

	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	memcpy(drv->iface, params->ifname, sizeof(drv->iface));
	strncpy(drv->master_iface, drv->iface, 5);
	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->ifindex = ifr.ifr_ifindex;
	os_strlcpy(ifr.ifr_name, drv->master_iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->master_ifindex = ifr.ifr_ifindex;

	drv->sock_xmit = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
					handle_read, drv, 1);
	if (drv->sock_xmit == NULL)
		goto bad;
#ifdef CONFIG_IEEE80211R
	drv->sock_tx_rrb = l2_packet_init("eth0", NULL, ETH_P_RRB,
					  hostapd_rrb_receive, drv, 1);
	if (drv->sock_tx_rrb == NULL)
		goto bad;
#endif
	if (l2_packet_get_own_addr(drv->sock_xmit, params->own_addr))
		goto bad;

	if (params->bridge[0]) {
		wpa_printf(MSG_DEBUG, "Configure bridge %s for EAPOL traffic.",
			   params->bridge[0]);
		drv->sock_recv = l2_packet_init(params->bridge[0], NULL,
						ETH_P_EAPOL, handle_read, drv,
						1);
		if (drv->sock_recv == NULL)
			goto bad;
#ifdef CONFIG_IEEE80211R
		drv->sock_rx_rrb = l2_packet_init(params->bridge[0], NULL,
						  ETH_P_RRB, hostapd_rrb_receive, drv,
						  1);
		if (drv->sock_rx_rrb == NULL)
			goto bad;
#endif
	} else if (linux_br_get(brname, drv->iface) == 0) {
		wpa_printf(MSG_DEBUG, "Interface in bridge %s; configure for "
			   "EAPOL receive", brname);
		drv->sock_recv = l2_packet_init(brname, NULL, ETH_P_EAPOL,
						handle_read, drv, 1);
		if (drv->sock_recv == NULL)
			goto bad;
#ifdef CONFIG_IEEE80211R
		drv->sock_rx_rrb = l2_packet_init(brname, NULL, ETH_P_RRB,
						  hostapd_rrb_receive, drv, 1);
		if (drv->sock_rx_rrb == NULL)
			goto bad;
#endif
	} else
		drv->sock_recv = drv->sock_xmit;

	if (marvell_wireless_event_init(drv))
		goto bad;

	/* for wps with open security and ieee8021x=0 mode */
	if (drv->hapd->conf->wps_state && !drv->hapd->conf->wpa) {
		if ( set80211param(drv, WL_PARAM_WPAWPA2MODE, 0x10, TRUE) ) {
			wpa_printf(MSG_DEBUG,"%s: WPS Extended Open mode setting failed\n", __func__);
			return NULL;
		}
	}

	return drv;
bad:
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv != NULL)
		free(drv);
	return NULL;
}


static void
marvell_deinit(void* priv) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_set_appie app_ie;

	app_ie.appBufLen = sizeof(app_ie.appBufLen) + sizeof(app_ie.appFrmType);
	app_ie.appFrmType = 0;
	set80211priv(priv, WL_IOCTL_SET_APPIE, &app_ie,
		     sizeof(app_ie.appFrmType) + sizeof(app_ie.appBufLen) +
		     app_ie.appBufLen);

	marvell_commit(priv);

	bitfield_free(capa_bits);
	bitfield_free(marvell_ext_capa_mask);

	netlink_deinit(drv->netlink);
	(void) linux_set_iface_flags(drv->ioctl_sock, drv->iface, 0);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv->sock_recv != NULL && drv->sock_recv != drv->sock_xmit)
		l2_packet_deinit(drv->sock_recv);
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	if (drv->sock_raw)
		l2_packet_deinit(drv->sock_raw);
#ifdef CONFIG_IEEE80211R
	if (drv->sock_tx_rrb != NULL)
		l2_packet_deinit(drv->sock_tx_rrb);
	if (drv->sock_rx_rrb != NULL)
		l2_packet_deinit(drv->sock_rx_rrb);
#endif
	free(drv);

}

static int
marvell_set_ssid(void *priv, const u8 *buf, int len) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;

	if (len > SSID_MAX_LEN)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;

	if (drv->we_version  < 21) {
		/* For historic reasons, set SSID length to include one extra
		 * character, C string nul termination, even though SSID is
		 * really an octet string that should not be presented as a C
		 * string. Some Linux drivers decrement the length by one and
		 * can thus end up missing the last octet of the SSID if the
		 * length is not incremented here. WE-21 changes this to
		 * explicitly require the length _not_ to include nul
		 * termination. */
		if (len)
			len++;
	}
	iwr.u.essid.length = len;

	if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		printf("len=%d\n", len);
		return -1;
	}
	if (drv->hapd->conf->wps_state ) {
		if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
			printf("ioctl[SIOCSIWCOMMIT]");
			return -1;
		}
	}
	return 0;
}
static int
marvell_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx,
		   u8 *seq) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_key wk;
	/*
		memset(&wk, 0, sizeof(wk));
		if (addr == NULL)
			memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		else
			memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = idx;

		if (get80211priv(drv, WL_IOCTL_GET_BIPKEYSN, &wk, sizeof(wk))<0) {
			wpa_printf(MSG_DEBUG,"%s: IOCTL Get SN failed\n", __func__);
			return -1;
		}
	    printf("### BIP SN-0: 0x%x ###\n", wk.ik_keytsc);

		memcpy(seq, &wk.ik_keytsc, 6);
	    printf("### seq-0: %x:%x:%x:%x:%x:%x ###\n", seq[0],
	            seq[1],
	            seq[2],
	            seq[3],
	            seq[4],
	            seq[5]);
	*/
	memset(&wk, 0, sizeof(wk));

	if (get80211param(drv, WL_PARAM_BIPKEYSN, &wk) < 0) {
		wpa_printf(MSG_DEBUG,"%s: IOCTL Get SN failed\n", __func__);
		return -1;
	}

	memcpy(seq, &wk, 6);
	printf("### seq: %x:%x:%x:%x:%x:%x ###\n", seq[0],
	       seq[1],
	       seq[2],
	       seq[3],
	       seq[4],
	       seq[5]);

	return 0;
}

static int
marvell_get_ssid(void *priv, u8 *buf, int len) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = SSID_MAX_LEN;

	if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;// -1; /*remove the '\0' */

	return ret;
}

static int
marvell_set_countermeasures(void *priv, int enabled) {
	struct marvell_driver_data *drv = priv;
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);

	return set80211param(drv, WL_PARAM_COUNTERMEASURES, enabled,FALSE);
}

static int
marvell_commit (void *priv) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
		printf("ioctl[SIOCSIWCOMMIT]");
		return -1;
	}

	return 0;
}

static int marvell_send_mlme(void *priv, const u8 *data, size_t data_len) {
	struct wlreq_set_mlme_send *mlme_frm;
	int res;

	mlme_frm = os_zalloc(data_len +2);
	if (mlme_frm == NULL)
		return -1;
	mlme_frm->len = data_len;
	memcpy(mlme_frm->buf, data, data_len);
	res = set80211priv(priv, WL_IOCTL_SET_MGMT_SEND, mlme_frm,
			   data_len+2);
	os_free(mlme_frm);
	return res;
}

static int marvell_send_action(void *priv, unsigned int freq,
			       unsigned int wait,
			       const u8 *dst, const u8 *src,
			       const u8 *bssid,
			       const u8 *data, size_t data_len, int no_cck) {
	struct wlreq_set_mlme_send *frm;
	u8 *mlme_send_buf;
	int res;

	frm = os_zalloc(data_len + IEEE80211_HDRLEN + 2);
	if (frm == NULL)
		return -1;
	mlme_send_buf = frm->buf;
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) mlme_send_buf;

	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	if (data[0] == 9)
		mgmt->frame_control |= host_to_le16(WLAN_FC_ISWEP);
	os_memcpy(mgmt->da, dst, ETH_ALEN);
	os_memcpy(mgmt->sa, src, ETH_ALEN);
	os_memcpy(mgmt->bssid, bssid, ETH_ALEN);
	os_memcpy(&mlme_send_buf[IEEE80211_HDRLEN], data, data_len);
	wpa_printf(MSG_DEBUG, "%s: wait=%u, dst=" MACSTR ", src="
		   MACSTR ", bssid=" MACSTR,
		   __func__, wait, MAC2STR(mgmt->da),
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->bssid));
	wpa_hexdump(MSG_MSGDUMP, "mrvl: act", (u8 *) mgmt, data_len+IEEE80211_HDRLEN);
	wpa_hexdump(MSG_MSGDUMP, "mrvl: data", data, data_len);

	frm->len = data_len + IEEE80211_HDRLEN;

	res = set80211priv(priv, WL_IOCTL_SET_MGMT_SEND, frm, frm->len+2);
	os_free(frm);
	return res;
}

static int marvell_sta_remove(void *priv, const u8 *addr) {
	return 	marvell_sta_deauth(priv, NULL, addr, WLAN_REASON_UNSPECIFIED);
}

__s32 marvell_freq_to_chnl(int freq) {
	__s32 chnl = 0;

	if ((2412<=freq) && (freq <= 2472)) {
		chnl = (freq - 2412)/5+1;
	} else if (freq == 2484) {
		chnl = 14;
	} else if (5180<=freq) {
		chnl = (freq - 5180)/5+36;
	}

	return chnl;
}

static int marvell_set_freq(void *priv, struct hostapd_freq_params *freq) {
	struct marvell_driver_data *drv  = priv;
	struct iwreq iwr;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "Marvell  Set freq %d channel %d)", freq->freq,
		   freq->channel);

	os_memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);

	if (freq->freq != 0)
		iwr.u.freq.m = marvell_freq_to_chnl(freq->freq);
	else
		iwr.u.freq.m = freq->channel;
	iwr.u.freq.e = 0;

	if (ioctl(drv->ioctl_sock, SIOCSIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);
	if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
		printf("ioctl[SIOCSIWCOMMIT]");
		return -1;
	}

	return ret;
}

static int marvell_set_bandsteer(void *priv, int enable) {
	struct marvell_driver_data *drv = priv;
	return set80211param(drv, WL_PARAM_BANDSTEER, enable, TRUE);
}

static int marvell_set_ap(void *priv,
			  struct wpa_driver_ap_params *params) {
	//struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret;
	int beacon_set;
	int num_suites;
	int smps_mode;
	u32 suites[10], suite;
	u32 ver;
	u8 buf[512];
	struct wlreq_set_appie * app_ie;
	int i;

	wpa_printf(MSG_DEBUG, "Marvell: Set beacon (beacon_set=%d)",
		   beacon_set);

	wpa_hexdump(MSG_DEBUG, "Marvell: Beacon head",
		    params->head, params->head_len);
	wpa_hexdump(MSG_DEBUG, "Marvell: Beacon tail",
		    params->tail, params->tail_len);
	wpa_printf(MSG_DEBUG, "Marvell: beacon_int=%d", params->beacon_int);
	wpa_printf(MSG_DEBUG, "Marvell: dtim_period=%d", params->dtim_period);
	wpa_hexdump_ascii(MSG_DEBUG, "Marvell: ssid",
			  params->ssid, params->ssid_len);
	if (params->proberesp && params->proberesp_len) {
		wpa_hexdump(MSG_DEBUG, "Marvell: proberesp (offload)",
			    params->proberesp, params->proberesp_len);
	}
	switch (params->hide_ssid) {
	case NO_SSID_HIDING:
		wpa_printf(MSG_DEBUG, "Marvell: hidden SSID not in use");
		break;
	case HIDDEN_SSID_ZERO_LEN:
		wpa_printf(MSG_DEBUG, "Marvell: hidden SSID zero len");
		break;
	case HIDDEN_SSID_ZERO_CONTENTS:
		wpa_printf(MSG_DEBUG, "Marvell: hidden SSID zero contents");
		break;
	}
	wpa_printf(MSG_DEBUG, "Marvell: privacy=%d", params->privacy);
	wpa_printf(MSG_DEBUG, "Marvell: auth_algs=0x%x", params->auth_algs);
	if ((params->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) ==
			(WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
		/* Leave out the attribute */
	} else if (params->auth_algs & WPA_AUTH_ALG_SHARED) {
	} else {
	}

	wpa_printf(MSG_DEBUG, "Marvell: wpa_version=0x%x", params->wpa_version);
	ver = 0;

	wpa_printf(MSG_DEBUG, "Marvell: key_mgmt_suites=0x%x",
		   params->key_mgmt_suites);
	num_suites = 0;
	if (params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X)
		suites[num_suites++] = WLAN_AKM_SUITE_8021X;
	if (params->key_mgmt_suites & WPA_KEY_MGMT_PSK)
		suites[num_suites++] = WLAN_AKM_SUITE_PSK;

	wpa_printf(MSG_DEBUG, "Marvell: pairwise_ciphers=0x%x",
		   params->pairwise_ciphers);
	//num_suites = wpa_cipher_to_cipher_suites(params->pairwise_ciphers,
	//suites, ARRAY_SIZE(suites));
	wpa_printf(MSG_DEBUG, "Marvell: group_cipher=0x%x",
		   params->group_cipher);
	//suite = wpa_cipher_to_cipher_suite(params->group_cipher);

	if (params->ht_opmode != -1) {
		switch (params->smps_mode) {
		case HT_CAP_INFO_SMPS_DYNAMIC:
			wpa_printf(MSG_DEBUG, "Marvell: SMPS mode - dynamic");
			break;
		case HT_CAP_INFO_SMPS_STATIC:
			wpa_printf(MSG_DEBUG, "Marvell: SMPS mode - static");
			break;
		default:
			/* invalid - fallback to smps off */
		case HT_CAP_INFO_SMPS_DISABLED:
			wpa_printf(MSG_DEBUG, "Marvell: SMPS mode - off");
			break;
		}
	}

	if (params->beacon_ies) {
		wpa_hexdump_buf(MSG_DEBUG, "Marvell: beacon_ies",
				params->beacon_ies);
		app_ie = (struct wlreq_set_appie *)buf;
		app_ie->appBufLen = wpabuf_len(params->beacon_ies);
		wpa_printf(MSG_DEBUG, "beacon ie len %d",
			   app_ie->appBufLen);

		if (params->beacon_ies->buf != NULL && app_ie->appBufLen != 0) {
			memcpy(&(app_ie->appBuf[0]), params->beacon_ies->buf ,
			       app_ie->appBufLen);
		} else {
			memset(&(app_ie->appBuf[0]), 0x00, IE_BUF_LEN);
			app_ie->appBufLen = IE_BUF_LEN;
		}
		app_ie->appFrmType = WL_APPIE_FRAMETYPE_BEACON;
		set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
			     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) +
			     app_ie->appBufLen);
	}

	if (params->proberesp_ies) {
		wpa_hexdump_buf(MSG_DEBUG, "Marvell: proberesp_ies",
				params->proberesp_ies);
		app_ie = (struct wlreq_set_appie *)buf;
		app_ie->appBufLen = params->proberesp_ies->size;

		if (params->proberesp_ies->buf != NULL && params->proberesp_ies->size
				!= 0) {
			memcpy(&(app_ie->appBuf[0]), params->proberesp_ies->buf ,
			       params->proberesp_ies->size);
		} else {
			memset(&(app_ie->appBuf[0]), 0x00, IE_BUF_LEN);
			app_ie->appBufLen = IE_BUF_LEN;
		}
		app_ie->appFrmType = WL_APPIE_FRAMETYPE_PROBE_RESP;
		set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
			     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) +
			     app_ie->appBufLen);
	}
	if (params->assocresp_ies) {
		wpa_hexdump_buf(MSG_DEBUG, "Marvell: assocresp_ies",
				params->assocresp_ies);
	}

	if (params->freq) {
		marvell_set_freq(priv, params->freq);
	}

	return ret;
fail:
	return -ENOBUFS;
}
#ifdef CONFIG_WLS_PF
u8 marvell_ext_capa[10] = {0};
static int marvell_get_capa(void *priv,
			    struct wpa_driver_capa *capa) {
	struct marvell_driver_data *drv = priv;
	wpa_printf(MSG_DEBUG, "%s %d\n", __FUNCTION__, drv->hapd->conf->interworking);

	if (!drv->hapd->conf->interworking) {
		bitfield_set(marvell_ext_capa_mask, 14);
		bitfield_set(marvell_ext_capa_mask, 15);
		bitfield_set(marvell_ext_capa_mask, 31);
		bitfield_set(marvell_ext_capa_mask, 70);
		bitfield_set(marvell_ext_capa_mask, 71);
		bitfield_clear(capa_bits, 14);
		bitfield_clear(capa_bits, 15);
		bitfield_clear(capa_bits, 31);
		bitfield_clear(capa_bits, 70);
		bitfield_clear(capa_bits, 71);
	} else {
		bitfield_clear(marvell_ext_capa_mask, 14);
		bitfield_clear(marvell_ext_capa_mask, 15);
		bitfield_clear(marvell_ext_capa_mask, 31);
		bitfield_clear(marvell_ext_capa_mask, 70);
		bitfield_clear(marvell_ext_capa_mask, 71);

		bitfield_set(capa_bits, 14);
		bitfield_set(capa_bits, 15);
		bitfield_set(capa_bits, 31);
		bitfield_set(capa_bits, 70);
		bitfield_set(capa_bits, 71);
	}
	capa->extended_capa = capa_bits->bits;
	capa->extended_capa_mask = marvell_ext_capa_mask->bits;
	capa->extended_capa_len = 10;

	return 0;
}
#endif
const struct wpa_driver_ops wpa_driver_marvell_ops = {
	.name			       	= "marvell",
	.hapd_init			= marvell_init,
	.deinit			       	= marvell_deinit,
	.set_ieee8021x		= marvell_set_ieee8021x,
	.set_key		        	= marvell_set_key,
	.flush			       	= marvell_flush,
	.set_generic_elem	    	= marvell_set_opt_ie,
	.read_sta_data		    	= marvell_read_sta_driver_data,
	.hapd_send_eapol	    	= marvell_send_eapol,
	.sta_disassoc			= marvell_sta_disassoc,
	.sta_deauth		       	= marvell_sta_deauth,
	.sta_remove                     = marvell_sta_remove,
	.hapd_set_ssid		    	= marvell_set_ssid,
	.hapd_get_ssid		= marvell_get_ssid,
	.set_countermeasures    	= marvell_set_countermeasures,
	.send_ether             	= marvell_send_ether,
	.send_action		    	= marvell_send_action,
	.send_mlme		       	= marvell_send_mlme,
	.set_ap_wps_ie		= marvell_set_ap_wps_ie,
	.get_seqnum			= marvell_get_seqnum,
	.commit                 		= marvell_commit,
#ifdef CONFIG_IEEE80211R
	.sta_auth				= marvell_sta_auth,
	.sta_assoc			= marvell_sta_assoc,
#endif
	.set_ap = marvell_set_ap,
#ifdef CONFIG_WLS_PF
	.get_capa = marvell_get_capa,
#endif
	.set_freq = marvell_set_freq,
	.set_bandsteer = marvell_set_bandsteer,
};
#else // HOSTAPD

// for wpa_supplicant
/* for wpa_supplicant */
#include "includes.h"
#include <sys/ioctl.h>

#include <netpacket/packet.h>

#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "common/ieee802_11_defs.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "wireless_copy.h"
#include "ap8xLnxIoctl.h"
#include "l2_packet/l2_packet.h"
#ifdef CONFIG_WLS_PF
#include "../../wpa_supplicant/bss.h"
#endif

#define	IEEE80211_ADDR_LEN	6
#define IE_BUF_LEN            8

#define printk printf

struct marvell_driver_data {
	void*  ctx;		/* back pointer */
	char	iface[IFNAMSIZ + 1];
	int     ifindex;
	char	master_iface[IFNAMSIZ + 1];
	int	master_ifindex;
	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
	struct l2_packet_data *sock_recv;	/* raw packet recv socket */
	int	ioctl_sock;			/* socket for ioctl() use */
	struct netlink_data *netlink;
	int	we_version;
	// +++++++++++++++++++++++++++++++++++
	u8	acct_mac[ETH_ALEN];
	struct hostap_sta_driver_data acct_data;
	u8 max_level;
	int		assoc_freq;
	u8	bssid[ETH_ALEN];
	int	operstate;
};

struct marvell_scan_data {
	struct wpa_scan_res res;
	u8 *ie;
	size_t ie_len;
	u8 ssid[32];
	size_t ssid_len;
	int maxrate;
};

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10Mbps              */
#endif //ARPHRD_ETHER

static void marvell_scan_timeout(void *eloop_ctx,
				 void *timeout_ctx);

static int marvell_set_freq(void *priv, int freq);
static int marvell_set_ssid(void *priv, const u8 *buf, int len);
static int marvell_set_bssid(void *priv, const u8 *buf);

#ifdef CONFIG_WPS
static void marvell_raw_recv_wps(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	/* Send Probe Request information to WPS processing */
	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ)
		return;

	os_memset(&event, 0, sizeof(event));
	event.rx_probe_req.sa = mgmt->sa;
	event.rx_probe_req.da = mgmt->da;
	event.rx_probe_req.bssid = mgmt->bssid;
	event.rx_probe_req.ie = mgmt->u.probe_req.variable;
	event.rx_probe_req.ie_len =
		len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
	wpa_supplicant_event(drv->ctx, EVENT_RX_PROBE_REQ, &event);
}
#endif /* CONFIG_WPS */

#if defined(CONFIG_WNM)
static void marvell_raw_recv_11v(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	union wpa_event_data event;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	u16 stype;

	if (len < IEEE80211_HDRLEN)
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: subtype 0x%x len %d", __func__, stype,
		   (int) len);

	/*
		if (os_memcmp(drv->own_addr, mgmt->bssid, ETH_ALEN) != 0) {
	    		wpa_printf(MSG_DEBUG, "%s: BSSID does not match - ignore",
	          			 __func__);
	    		return;
			}
		*/

	switch (stype) {
	case WLAN_FC_STYPE_ACTION:
		if (&mgmt->u.action.category > buf + len)
			break;
		if (mgmt->u.action.category == WLAN_ACTION_WNM) {
			os_memset(&event, 0, sizeof(event));
			event.rx_action.da = mgmt->da;
			event.rx_action.sa = mgmt->sa;
			event.rx_action.bssid = mgmt->bssid;
			event.rx_action.category = mgmt->u.action.category;
			event.rx_action.data = &mgmt->u.action.category;
			event.rx_action.len = buf + len - event.rx_action.data;
			event.rx_mgmt.frame = buf;
			event.rx_mgmt.frame_len = len;
			wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
		} else
			printf("Not WNM Action ...\n");
		break;
	default:
		break;
	}
}
#endif /* CONFIG_WNM */

#ifdef CONFIG_IEEE80211R
static void marvell_raw_recv_11r(void *ctx, const u8 *src_addr, const u8 *buf,
				 size_t len) {
	struct marvell_driver_data *drv = ctx;
	union wpa_event_data event;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	u16 stype;

	if (len < IEEE80211_HDRLEN)
		return;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;
	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: subtype 0x%x len %d", __func__, stype, (int) len);

	switch (stype) {
	case WLAN_FC_STYPE_ACTION:
		if (&mgmt->u.action.category > buf + len)
			break;
		if ((mgmt->u.action.category == WLAN_ACTION_FT) || (mgmt->u.action.category == WLAN_ACTION_PUBLIC)
				|| (mgmt->u.action.category == WLAN_ACTION_PROTECTED_DUAL)) {
			os_memset(&event, 0, sizeof(event));
			event.rx_action.da = mgmt->da;
			event.rx_action.sa = mgmt->sa;
			event.rx_action.bssid = mgmt->bssid;
			event.rx_action.category = mgmt->u.action.category;
			event.rx_action.data = &mgmt->u.action.category;
			event.rx_action.len = buf + len - event.rx_action.data;
			event.rx_mgmt.frame = buf;
			event.rx_mgmt.frame_len = len;
			wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
		} else
			printf("Not FT Action ...\n");
		break;
	case WLAN_FC_STYPE_AUTH:
		if (len - IEEE80211_HDRLEN < sizeof(mgmt->u.auth))
			break;
		os_memset(&event, 0, sizeof(event));
		os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
		os_memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
		event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
		event.auth.auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
		event.auth.status_code = le_to_host16(mgmt->u.auth.status_code);
		event.auth.ies = mgmt->u.auth.variable;
		event.auth.ies_len = len - IEEE80211_HDRLEN -sizeof(mgmt->u.auth);
		wpa_supplicant_event(drv->ctx, EVENT_AUTH, &event);
		break;

	default:
		break;
	}
}
#endif /* CONFIG_WNM */

//#if defined(CONFIG_WPS) || defined(CONFIG_WNM) || defined(CONFIG_HS20) || defined(CONFIG_IEEE80211R)
static void marvell_raw_receive(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len) {
#ifdef CONFIG_WPS
	marvell_raw_recv_wps(ctx, src_addr, buf, len);
#endif /* CONFIG_WPS */
#if defined(CONFIG_WNM)
	marvell_raw_recv_11v(ctx, src_addr, buf, len);
#endif /* CONFIG_WNM */
#ifdef CONFIG_HS20
	marvell_raw_recv_hs20(ctx, src_addr, buf, len);
#endif /* CONFIG_HS20 */
#ifdef CONFIG_IEEE80211R
	marvell_raw_recv_11r(ctx, src_addr, buf, len);
#endif
}
//#endif /* CONFIG_WPS || CONFIG_WNM || CONFIG_HS20 */

static const char *
ether_sprintf(const u8 *addr) {
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}

static int marvell_wext_19_iw_point(struct marvell_driver_data *drv, u16 cmd) {
	return drv->we_version > 18 &&
	       (cmd == SIOCGIWESSID || cmd == SIOCGIWENCODE ||
		cmd == IWEVGENIE || cmd == IWEVCUSTOM);
}

static int
set80211priv(struct marvell_driver_data *drv, int op, void *data, int len) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
		return -1;
	}

	return 0;
}
#if 1
static int
get80211priv(struct marvell_driver_data *drv, int op, void *data, int len) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
		return -1;
	}

	if (len < IFNAMSIZ)
		memcpy(data, iwr.u.name, len);
	return iwr.u.data.length;
}
#endif //0

static int
set80211param(struct marvell_driver_data *drv, int op, int arg, Boolean commit) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	if ((op == WL_PARAM_HTBANDWIDTH) || (op == WL_PARAM_AUTOCHANNEL))
		strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);
	else
		strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

	iwr.u.mode = op;
	memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

	if (ioctl(drv->ioctl_sock, WL_IOCTL_WL_PARAM, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_WL_PARAM]");
		return -1;
	}

	if (commit) {
		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
		if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
			printf("ioctl[SIOCSIWCOMMIT]");
			return -1;
		}
	}
	return 0;
}

#if 0
static int
get80211param(struct marvell_driver_data *drv, int op, void *value) {
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = op;
	//memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

	if (ioctl(drv->ioctl_sock, WL_IOCTL_WL_GET_PARAM, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_WL_GET_PARAM]");
		return -1;
	}
	printf("size=%d\n", sizeof(iwr.u));
	if (sizeof(int) < IFNAMSIZ)
		memcpy(value, iwr.u.name, sizeof(iwr.u));
	return 0;
}
#endif //0

static int
marvell_get_ssid(void *priv, u8 *ssid) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;
	printf("=>%s()\n", __func__);
	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) ssid;
	iwr.u.essid.length = SSID_MAX_LEN;

	if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;// -1; /*remove the '\0' */
	printf("<=%s(), %d\n", __func__, ret);
	return ret;
}


int marvell_get_bssid(void *priv, u8 *bssid) {
	struct marvell_driver_data *drv = priv;
	int ret = 0;

	os_memcpy(bssid, drv->bssid, ETH_ALEN);
	return ret;
}


static int
marvell_set_countermeasures(void *priv, int enabled) {
	struct marvell_driver_data *drv = priv;
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
	return set80211param(drv, WL_PARAM_COUNTERMEASURES, enabled,FALSE);
}

static int
marvell_commit(void *priv, const char *ifname) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
		printf("ioctl[SIOCSIWCOMMIT]");
		return -1;
	}
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
		printf("ioctl[SIOCSIWCOMMIT]");
		return -1;
	}


	return 0;
}

#if 0
static int marvell_send_mlme(void *priv, const u8 *data, size_t data_len) {
	struct wlreq_set_mlme_send *mlme_frm;
	int res;

	mlme_frm = os_zalloc(data_len +2);
	if (mlme_frm == NULL)
		return -1;
	mlme_frm->len = data_len;
	memcpy(mlme_frm->buf, data, data_len);
	res = set80211priv(priv, WL_IOCTL_SET_MGMT_SEND, mlme_frm,
			   data_len+2);
	os_free(mlme_frm);
	return res;
}
#endif //0

static int marvell_send_action(void *priv, unsigned int freq,
			       unsigned int wait,
			       const u8 *dst, const u8 *src,
			       const u8 *bssid,
			       const u8 *data, size_t data_len, int no_cck) {
	struct wlreq_set_mlme_send *frm;
	u8 *mlme_send_buf;
	int res;

	frm = os_zalloc(data_len + IEEE80211_HDRLEN + 2);
	if (frm == NULL) {
		return -1;
	}

	marvell_set_freq(priv,freq);

	mlme_send_buf = frm->buf;
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) mlme_send_buf;

	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
	if (data[0] == 9)
		mgmt->frame_control |= host_to_le16(WLAN_FC_ISWEP);

	os_memcpy(mgmt->da, dst, ETH_ALEN);
	os_memcpy(mgmt->sa, src, ETH_ALEN);
	os_memcpy(mgmt->bssid, bssid, ETH_ALEN);
	os_memcpy(&mlme_send_buf[IEEE80211_HDRLEN], data, data_len);
	wpa_printf(MSG_DEBUG, "%s: wait=%u, dst=" MACSTR ", src="
		   MACSTR ", bssid=" MACSTR,
		   __func__, wait, MAC2STR(mgmt->da),
		   MAC2STR(mgmt->sa), MAC2STR(mgmt->bssid));
	wpa_hexdump(MSG_MSGDUMP, "mrvl: act", (u8 *) mgmt, data_len+IEEE80211_HDRLEN);
	wpa_hexdump(MSG_MSGDUMP, "mrvl: data", data, data_len);

	frm->len = data_len + IEEE80211_HDRLEN;

	res = set80211priv(priv, WL_IOCTL_SET_MGMT_SEND, frm, frm->len+2);
	os_free(frm);

	return res;
}

static void
marvell_wireless_event_wireless_custom(struct marvell_driver_data *drv,
				       char *custom) {
//	wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		char *pos;
		u8 addr[ETH_ALEN];
		pos = strstr(custom, "addr=");
		if (pos == NULL) {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "without sender address ignored");
			return;
		}
		pos += 5;
		if (hwaddr_aton(pos, addr) == 0) {
			union wpa_event_data data;
			os_memset(&data, 0, sizeof(data));
			data.michael_mic_failure.unicast = 1;
			data.michael_mic_failure.src = NULL;
			wpa_supplicant_event(drv->ctx,
					     EVENT_MICHAEL_MIC_FAILURE, &data);
		} else {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "with invalid MAC address");
		}
	} else if (strncmp(custom, "STA-TRAFFIC-STAT", 16) == 0) {
		char *key, *value;
		u32 val;
		key = custom;
		while ((key = strchr(key, '\n')) != NULL) {
			key++;
			value = strchr(key, '=');
			if (value == NULL)
				continue;
			*value++ = '\0';
			val = strtoul(value, NULL, 10);
			if (strcmp(key, "mac") == 0)
				hwaddr_aton(value, drv->acct_mac);
			else if (strcmp(key, "rx_packets") == 0)
				drv->acct_data.rx_packets = val;
			else if (strcmp(key, "tx_packets") == 0)
				drv->acct_data.tx_packets = val;
			else if (strcmp(key, "rx_bytes") == 0)
				drv->acct_data.rx_bytes = val;
			else if (strcmp(key, "tx_bytes") == 0)
				drv->acct_data.tx_bytes = val;
			key = value;
		}
	} else if (strncmp(custom, "mlme-probe_request", strlen("mlme-probe_request")) == 0) {
#define MLME_FRAME_TAG_SIZE  20
#ifdef MRVL_WPS2
		s16 len = WPA_GET_LE16(custom + strlen("mlme-probe_request"));
#else
		s16 len = *(custom + 18);
#endif
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-probe_request "
				   "length %d", len);
			return;
		}

		marvell_raw_receive(drv, NULL, (u8 *) custom + MLME_FRAME_TAG_SIZE, len);
	}
#ifdef CONFIG_IEEE80211R
	else if (strncmp(custom, "mlme-action", strlen("mlme-action")) == 0) {
		s16 len = WPA_GET_LE16(custom + strlen("mlme-action"));
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-action"
				   "length %d", len);
			return;
		}
		marvell_raw_receive(drv, NULL, (u8 *) custom +
				    strlen("mlme-action")+2, len);
	} else if (strncmp(custom, "mlme-auth", strlen("mlme-auth")) == 0) {
		s16 len = WPA_GET_LE16(custom+strlen("mlme-auth"));
		if (len < 0) {
			wpa_printf(MSG_DEBUG, "mlme-auth"
				   "length %d", len);
			return;
		}
		marvell_raw_receive(drv, NULL, (u8 *) custom+strlen("mlme-auth")+2, len);
	}
#endif
	else if (strncmp(custom + 18, "STA MLME - Client scan completed ", strlen("STA MLME - Client scan completed ")) == 0) {
		eloop_cancel_timeout(marvell_scan_timeout, drv, drv->ctx);
		wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);

	} else if (strstr(custom, "Unexpected event - External recovery recommended: ") != NULL) {
		printf("received recovery event rebooting\n");
		system("reboot");
	}
}

#if 0
static void marvell_driver_wext_event_assoc_ies(struct marvell_driver_data *drv) {
	union wpa_event_data data;

	if (drv->assoc_req_ies == NULL && drv->assoc_resp_ies == NULL)
		return;

	os_memset(&data, 0, sizeof(data));

	if (drv->assoc_req_ies) {
		data.assoc_info.req_ies = drv->assoc_req_ies;
		data.assoc_info.req_ies_len = drv->assoc_req_ies_len;
	}
	if (drv->assoc_resp_ies) {
		data.assoc_info.resp_ies = drv->assoc_resp_ies;
		data.assoc_info.resp_ies_len = drv->assoc_resp_ies_len;
	}
	data.assoc_info.freq = ;

	wpa_supplicant_event(drv->ctx, EVENT_ASSOCINFO, &data);

	os_free(drv->assoc_req_ies);
//	drv->assoc_req_ies = NULL;
	os_free(drv->assoc_resp_ies);
//	drv->assoc_resp_ies = NULL;
}
#endif //0

static void
marvell_wireless_event_wireless(struct marvell_driver_data *drv,
				char *data, int len) {
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;
	union wpa_event_data assoc_data;
	u8 nullBssid[ETH_ALEN] = {0};

	pos = data;
	end = data + len;
	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
				(iwe->cmd == IWEVMICHAELMICFAILURE ||
				 iwe->cmd == IWEVASSOCREQIE ||
				 iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}
		switch (iwe->cmd) {
		case SIOCSIWESSID:
			break;
		case IWEVEXPIRED:
			memset(drv->bssid, 0, ETH_ALEN);
			drv_event_disassoc(drv->ctx,
					   (u8 *) iwe->u.addr.sa_data);
			wpa_printf(MSG_DEBUG, "Marvell: IWEVEXPIRED\n");
			break;
		case IWEVREGISTERED:
			wpa_printf(MSG_DEBUG, "Marvell: IWEVREGISTERED\n");
			//if (!memcmp(drv->bssid, nullBssid, ETH_ALEN)) {
				memcpy(drv->bssid, (u8 *)iwe->u.addr.sa_data, ETH_ALEN);
				memset(&assoc_data, 0, sizeof(assoc_data));
				assoc_data.assoc_info.authorized = 1;
				wpa_supplicant_event(drv->ctx, EVENT_ASSOC,
						     NULL);
			//}

			break;
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;		/* XXX */
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			marvell_wireless_event_wireless_custom(drv, buf);
			free(buf);
			break;
		}

		pos += iwe->len;
	}
	return;
}

static void
marvell_wireless_event_rtm_newlink(void *ctx,
				   struct ifinfomsg *ifi, u8 *buf, size_t len) {
#if 1
	struct marvell_driver_data *drv = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;
	char ifname[IFNAMSIZ + 1];

	if ((ifi->ifi_index != drv->master_ifindex) &&
			(ifi->ifi_index != drv->ifindex))
		return;

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			marvell_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		} else if (attr->rta_type == IFLA_IFNAME) {
			if (RTA_PAYLOAD(attr) >= IFNAMSIZ)
				break;
			os_memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));
			ifname[RTA_PAYLOAD(attr)] = '\0';
		}

		attr = RTA_NEXT(attr, attrlen);
	}
#else
	struct marvell_driver_data *drv = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;
	char namebuf[IFNAMSIZ];

	if (!wpa_driver_wext_own_ifindex(drv, ifi->ifi_index, buf, len)) {
		wpa_printf(MSG_DEBUG, "Ignore event for foreign ifindex %d",
			   ifi->ifi_index);
		printk("Ignore event for foreign ifindex %d",
		       ifi->ifi_index);
		return;
	}

///	wpa_printf(MSG_DEBUG, "RTM_NEWLINK: operstate=%d ifi_flags=0x%x "
//		   "(%s%s%s%s)",
//		   drv->operstate, ifi->ifi_flags,
//		   (ifi->ifi_flags & IFF_UP) ? "[UP]" : "",
//		   (ifi->ifi_flags & IFF_RUNNING) ? "[RUNNING]" : "",
//		   (ifi->ifi_flags & IFF_LOWER_UP) ? "[LOWER_UP]" : "",
//		   (ifi->ifi_flags & IFF_DORMANT) ? "[DORMANT]" : "");

//	if (!drv->if_disabled && !(ifi->ifi_flags & IFF_UP)) {
//		wpa_printf(MSG_DEBUG, "WEXT: Interface down");
//		drv->if_disabled = 1;
//		wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_DISABLED, NULL);
//	}

	if (drv->if_disabled && (ifi->ifi_flags & IFF_UP)) {
		if (if_indextoname(ifi->ifi_index, namebuf) &&
				linux_iface_up(drv->ioctl_sock, drv->ifname) == 0) {
			wpa_printf(MSG_DEBUG, "WEXT: Ignore interface up "
				   "event since interface %s is down",
				   namebuf);
		} else if (if_nametoindex(drv->ifname) == 0) {
			wpa_printf(MSG_DEBUG, "WEXT: Ignore interface up "
				   "event since interface %s does not exist",
				   drv->ifname);
		} else if (drv->if_removed) {
			wpa_printf(MSG_DEBUG, "WEXT: Ignore interface up "
				   "event since interface %s is marked "
				   "removed", drv->ifname);
		} else {
			wpa_printf(MSG_DEBUG, "WEXT: Interface up");
			drv->if_disabled = 0;
			wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_ENABLED,
					     NULL);
		}
	}

	/*
	 * Some drivers send the association event before the operup event--in
	 * this case, lifting operstate in wpa_driver_wext_set_operstate()
	 * fails. This will hit us when wpa_supplicant does not need to do
	 * IEEE 802.1X authentication
	 */
	if (drv->operstate == 1 &&
			(ifi->ifi_flags & (IFF_LOWER_UP | IFF_DORMANT)) == IFF_LOWER_UP &&
			!(ifi->ifi_flags & IFF_RUNNING))
		netlink_send_oper_ifla(drv->netlink, drv->ifindex,
				       -1, IF_OPER_UP);

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			wpa_driver_wext_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		} else if (attr->rta_type == IFLA_IFNAME) {
			wpa_driver_wext_event_link(drv,
						   ((char *) attr) + rta_len,
						   attr->rta_len - rta_len, 0);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
#endif //0
}

static int
marvell_get_we_version(struct marvell_driver_data *drv) {
	struct iw_range *range;
	struct iwreq iwr;
	int minlen;
	size_t buflen;

	drv->we_version = 0;

	/*
	 * Use larger buffer than struct iw_range in order to allow the
	 * structure to grow in the future.
	 */
	buflen = sizeof(struct iw_range) + 500;
	range = os_zalloc(buflen);
	if (range == NULL)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) range;
	iwr.u.data.length = buflen;

	minlen = ((char *) &range->enc_capa) - (char *) range +
		 sizeof(range->enc_capa);

	if (ioctl(drv->ioctl_sock, SIOCGIWRANGE, &iwr) < 0) {
		perror("ioctl[SIOCGIWRANGE]");
		free(range);
		return -1;
	} else if (iwr.u.data.length >= minlen &&
			range->we_version_compiled >= 18) {
		wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
			   "WE(source)=%d enc_capa=0x%x",
			   range->we_version_compiled,
			   range->we_version_source,
			   range->enc_capa);
		drv->we_version = range->we_version_compiled;
	}

	free(range);
	return 0;
}

static int
marvell_wireless_event_init(struct marvell_driver_data *drv) {
	struct netlink_config *cfg;

	marvell_get_we_version(drv);

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = drv;
	cfg->newlink_cb = marvell_wireless_event_rtm_newlink;
	drv->netlink = netlink_init(cfg);
	if (drv->netlink == NULL) {
		os_free(cfg);
		return -1;
	}

	return 0;
}


static u8 * marvell_giwscan(struct marvell_driver_data *drv,
			    size_t *len) {
	struct iwreq iwr;
	u8 *res_buf;
	size_t res_buf_len;

	res_buf_len = IW_SCAN_MAX_DATA;
	for (;;) {
		res_buf = os_malloc(res_buf_len);
		if (res_buf == NULL)
			return NULL;
		os_memset(&iwr, 0, sizeof(iwr));
		os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
		iwr.u.data.pointer = res_buf;
		iwr.u.data.length = res_buf_len;

		if (ioctl(drv->ioctl_sock, SIOCGIWSCAN, &iwr) == 0)
			break;

		if (errno == E2BIG && res_buf_len < 65535) {
			os_free(res_buf);
			res_buf = NULL;
			res_buf_len *= 2;
			if (res_buf_len > 65535)
				res_buf_len = 65535; /* 16-bit length field */
			wpa_printf(MSG_DEBUG, "Scan results did not fit - "
				   "trying larger buffer (%lu bytes)",
				   (unsigned long) res_buf_len);
		} else {
			perror("ioctl[SIOCGIWSCAN]");
			os_free(res_buf);
			return NULL;
		}
	}

	if (iwr.u.data.length > res_buf_len) {
		os_free(res_buf);
		return NULL;
	}
	*len = iwr.u.data.length;

	return res_buf;
}

static void marvell_add_scan_entry(struct wpa_scan_results *res,
				   struct marvell_scan_data *data) {
	struct wpa_scan_res **tmp;
	struct wpa_scan_res *r;
	size_t extra_len;
	u8 *pos, *end, *ssid_ie = NULL, *rate_ie = NULL;

	/* Figure out whether we need to fake any IEs */
	pos = data->ie;
	end = pos + data->ie_len;
	while (pos && pos + 1 < end) {
		if (pos + 2 + pos[1] > end)
			break;
		if (pos[0] == WLAN_EID_SSID)
			ssid_ie = pos;
		else if (pos[0] == WLAN_EID_SUPP_RATES)
			rate_ie = pos;
		else if (pos[0] == WLAN_EID_EXT_SUPP_RATES)
			rate_ie = pos;
		pos += 2 + pos[1];
	}

	extra_len = 0;
	if (ssid_ie == NULL)
		extra_len += 2 + data->ssid_len;
	if (rate_ie == NULL && data->maxrate)
		extra_len += 3;

	r = os_zalloc(sizeof(*r) + extra_len + data->ie_len);
	if (r == NULL)
		return;
	os_memcpy(r, &data->res, sizeof(*r));
	r->ie_len = extra_len + data->ie_len;
	pos = (u8 *) (r + 1);
	if (ssid_ie == NULL) {
		/*
		 * Generate a fake SSID IE since the driver did not report
		 * a full IE list.
		 */
		*pos++ = WLAN_EID_SSID;
		*pos++ = data->ssid_len;
		os_memcpy(pos, data->ssid, data->ssid_len);
		pos += data->ssid_len;
	}
	if (rate_ie == NULL && data->maxrate) {
		/*
		 * Generate a fake Supported Rates IE since the driver did not
		 * report a full IE list.
		 */
		*pos++ = WLAN_EID_SUPP_RATES;
		*pos++ = 1;
		*pos++ = data->maxrate;
	}
	if (data->ie)
		os_memcpy(pos, data->ie, data->ie_len);

	tmp = os_realloc_array(res->res, res->num + 1,
			       sizeof(struct wpa_scan_res *));
	if (tmp == NULL) {
		os_free(r);
		return;
	}
	tmp[res->num++] = r;
	res->res = tmp;
}

static void marvell_get_scan_mode(struct iw_event *iwe,
				  struct marvell_scan_data *res) {
	if (iwe->u.mode == IW_MODE_ADHOC)
		res->res.caps |= IEEE80211_CAP_IBSS;
	else if (iwe->u.mode == IW_MODE_MASTER || iwe->u.mode == IW_MODE_INFRA)
		res->res.caps |= IEEE80211_CAP_ESS;
}


static void marvell_get_scan_ssid(struct iw_event *iwe,
				  struct marvell_scan_data *res, char *custom,
				  char *end) {
	int ssid_len = iwe->u.essid.length;
	if (custom + ssid_len > end)
		return;
	if (iwe->u.essid.flags &&
			ssid_len > 0 &&
			ssid_len <= IW_ESSID_MAX_SIZE) {
		os_memcpy(res->ssid, custom, ssid_len);
		res->ssid_len = ssid_len;
	}
}


static void marvell_get_scan_freq(struct iw_event *iwe,
				  struct marvell_scan_data *res) {
	int divi = 1000000, i;

	if (iwe->u.freq.e == 0) {
		/*
		 * Some drivers do not report frequency, but a channel.
		 * Try to map this to frequency by assuming they are using
		 * IEEE 802.11b/g.  But don't overwrite a previously parsed
		 * frequency if the driver sends both frequency and channel,
		 * since the driver may be sending an A-band channel that we
		 * don't handle here.
		 */
		if (res->res.freq)
			return;

		if (iwe->u.freq.m >= 1 && iwe->u.freq.m <= 13) {
			res->res.freq = 2407 + 5 * iwe->u.freq.m;
			return;
		} else if (iwe->u.freq.m == 14) {
			res->res.freq = 2484;
			return;
		} else if (iwe->u.freq.m >= 36) {
			res->res.freq = 5180 + 5 * (iwe->u.freq.m - 36);
			return;
		}
	}

	if (iwe->u.freq.e > 6) {
		wpa_printf(MSG_DEBUG, "Invalid freq in scan results (BSSID="
			   MACSTR " m=%d e=%d)",
			   MAC2STR(res->res.bssid), iwe->u.freq.m,
			   iwe->u.freq.e);
		return;
	}

	for (i = 0; i < iwe->u.freq.e; i++)
		divi /= 10;
	res->res.freq = iwe->u.freq.m / divi;
	return;
}


static void marvell_get_scan_qual(struct marvell_driver_data *drv,
				  struct iw_event *iwe,
				  struct marvell_scan_data *res) {
	res->res.qual = iwe->u.qual.qual;
	res->res.noise = iwe->u.qual.noise;
	res->res.level = iwe->u.qual.level;
	if (iwe->u.qual.updated & IW_QUAL_QUAL_INVALID)
		res->res.flags |= WPA_SCAN_QUAL_INVALID;
	if (iwe->u.qual.updated & IW_QUAL_LEVEL_INVALID)
		res->res.flags |= WPA_SCAN_LEVEL_INVALID;
	if (iwe->u.qual.updated & IW_QUAL_NOISE_INVALID)
		res->res.flags |= WPA_SCAN_NOISE_INVALID;
	if (iwe->u.qual.updated & IW_QUAL_DBM)
		res->res.flags |= WPA_SCAN_LEVEL_DBM;
	if ((iwe->u.qual.updated & IW_QUAL_DBM) ||
			((iwe->u.qual.level != 0) &&
			 (iwe->u.qual.level > drv->max_level))) {
		if (iwe->u.qual.level >= 64)
			res->res.level -= 0x100;
		if (iwe->u.qual.noise >= 64)
			res->res.noise -= 0x100;
	}
}


static void marvell_get_scan_encode(struct iw_event *iwe,
				    struct marvell_scan_data *res) {
	if (!(iwe->u.data.flags & IW_ENCODE_DISABLED))
		res->res.caps |= IEEE80211_CAP_PRIVACY;
}


static void marvell_get_scan_rate(struct iw_event *iwe,
				  struct marvell_scan_data *res, char *pos,
				  char *end) {
	int maxrate;
	char *custom = pos + IW_EV_LCP_LEN;
	struct iw_param p;
	size_t clen;

	clen = iwe->len;
	if (custom + clen > end)
		return;
	maxrate = 0;
	while (((ssize_t) clen) >= (ssize_t) sizeof(struct iw_param)) {
		/* Note: may be misaligned, make a local, aligned copy */
		os_memcpy(&p, custom, sizeof(struct iw_param));
		if (p.value > maxrate)
			maxrate = p.value;
		clen -= sizeof(struct iw_param);
		custom += sizeof(struct iw_param);
	}

	/* Convert the maxrate from WE-style (b/s units) to
	 * 802.11 rates (500000 b/s units).
	 */
	res->maxrate = maxrate / 500000;
}


static void marvell_get_scan_iwevgenie(struct iw_event *iwe,
				       struct marvell_scan_data *res, char *custom,
				       char *end) {
	char *genie, *gpos, *gend;
	u8 *tmp;

	if (iwe->u.data.length == 0)
		return;

	gpos = genie = custom;
	gend = genie + iwe->u.data.length;
	if (gend > end) {
		wpa_printf(MSG_INFO, "IWEVGENIE overflow");
		return;
	}

	tmp = os_realloc(res->ie, res->ie_len + gend - gpos);
	if (tmp == NULL)
		return;
	os_memcpy(tmp + res->ie_len, gpos, gend - gpos);
	res->ie = tmp;
	res->ie_len += gend - gpos;
}


static void marvell_get_scan_custom(struct iw_event *iwe,
				    struct marvell_scan_data *res, char *custom,
				    char *end) {
	size_t clen;
	u8 *tmp;

	clen = iwe->u.data.length;
	if (custom + clen > end)
		return;

	if (clen > 9 && os_strncmp(custom, "WPA_IE = ", 9) == 0) {
		char *spos;
		int bytes;
		spos = custom + 9;
		bytes = custom + clen - spos;
		if (bytes & 1 || bytes == 0)
			return;
		bytes /= 2;
		tmp = os_realloc(res->ie, res->ie_len + bytes);
		if (tmp == NULL)
			return;
		res->ie = tmp;
		if (hexstr2bin(spos, tmp + res->ie_len, bytes) < 0)
			return;
		res->ie_len += bytes;
	} else if (clen > 10 && os_strncmp(custom, "WPA2_IE = ", 10) == 0) {
		char *spos;
		int bytes;
		spos = custom + 10;
		bytes = custom + clen - spos;
		if (bytes & 1 || bytes == 0)
			return;
		bytes /= 2;
		tmp = os_realloc(res->ie, res->ie_len + bytes);
		if (tmp == NULL)
			return;
		res->ie = tmp;
		if (hexstr2bin(spos, tmp + res->ie_len, bytes) < 0)
			return;
		res->ie_len += bytes;
	} else if (clen > 4 && os_strncmp(custom, "tsf=", 4) == 0) {
		char *spos;
		int bytes;
		u8 bin[8];
		spos = custom + 4;
		bytes = custom + clen - spos;
		if (bytes != 16) {
			wpa_printf(MSG_INFO, "Invalid TSF length (%d)", bytes);
			return;
		}
		bytes /= 2;
		if (hexstr2bin(spos, bin, bytes) < 0) {
			wpa_printf(MSG_DEBUG, "WEXT: Invalid TSF value");
			return;
		}
		res->res.tsf += WPA_GET_BE64(bin);
	} else if (clen > 14 && os_strncmp(custom, "EXP_CAPS_IE = ", 14) == 0) {
		char *spos;
		int bytes;
		spos = custom + 14;
		bytes = custom + clen - spos;
		if (bytes & 1 || bytes == 0)
			return;
		bytes /= 2;
		tmp = os_realloc(res->ie, res->ie_len + bytes);
		if (tmp == NULL)
			return;
		res->ie = tmp;
		if (hexstr2bin(spos, tmp + res->ie_len, bytes) < 0)
			return;
		res->ie_len += bytes;
		wpa_printf(MSG_DEBUG, "WEXT: extended caps IE\n");
		wpa_hexdump(MSG_DEBUG,"scan result", res->ie, res->ie_len);
	}
#ifdef CONFIG_MULTI_AP
	else if (clen >= 15 && os_strncmp(custom, "MAP_BSSMODE = ", 14) == 0)
		res->res.map_bss_mode = atoi(custom + 14);
#endif /* CONFIG_MULTI_AP */
#if defined(CONFIG_WNM)
	else if (clen >= 14 && os_strncmp(custom, "BcnInterval = ", 14) == 0)
		res->res.beacon_int = atoi(custom + 14);
#endif /* CONFIG_WNM */
}

struct wpa_scan_results * marvell_get_scan_results(void *priv) {
	struct marvell_driver_data *drv = priv;
	size_t len;
	int first;
	u8 *res_buf;
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom;
	struct wpa_scan_results *res;
	struct marvell_scan_data data;
	res_buf = marvell_giwscan(drv, &len);
	if (res_buf == NULL) {
		return NULL;
	}

	first = 1;

	res = os_zalloc(sizeof(*res));
	if (res == NULL) {
		os_free(res_buf);
		return NULL;
	}

	pos = (char *) res_buf;
	end = (char *) res_buf + len;
	os_memset(&data, 0, sizeof(data));

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			break;

		custom = pos + IW_EV_POINT_LEN;
		if (marvell_wext_19_iw_point(drv, iwe->cmd)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			os_memcpy(dpos, pos + IW_EV_LCP_LEN,
				  sizeof(struct iw_event) - dlen);
		} else {
			os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case SIOCGIWAP:
			if (!first)
				marvell_add_scan_entry(res, &data);
			first = 0;
			os_free(data.ie);
			os_memset(&data, 0, sizeof(data));
			os_memcpy(data.res.bssid,
				  iwe->u.ap_addr.sa_data, ETH_ALEN);
			break;
		case SIOCGIWMODE:
			marvell_get_scan_mode(iwe, &data);
			break;
		case SIOCGIWESSID:
			marvell_get_scan_ssid(iwe, &data, custom, end);
			break;
		case SIOCGIWFREQ:
			marvell_get_scan_freq(iwe, &data);
			break;
		case IWEVQUAL:
			marvell_get_scan_qual(drv, iwe, &data);
			break;
		case SIOCGIWENCODE:
			marvell_get_scan_encode(iwe, &data);
			break;
		case SIOCGIWRATE:
			marvell_get_scan_rate(iwe, &data, pos, end);
			break;
		case IWEVGENIE:
			marvell_get_scan_iwevgenie(iwe, &data, custom, end);
			break;
		case IWEVCUSTOM:
			marvell_get_scan_custom(iwe, &data, custom, end);
			eloop_cancel_timeout(marvell_scan_timeout, drv, drv->ctx);
			break;
		default:
			break;
		}

		pos += iwe->len;
	}
	os_free(res_buf);
	res_buf = NULL;
	if (!first)
		marvell_add_scan_entry(res, &data);
	os_free(data.ie);

	wpa_printf(MSG_DEBUG, "Received %lu bytes of scan results (%lu BSSes)",
		   (unsigned long) len, (unsigned long) res->num);
	return res;
}



static void marvell_scan_timeout(void *eloop_ctx,
				 void *timeout_ctx) {
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}

static int marvell_scan(void *priv,
			struct wpa_driver_scan_params *params) {

	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;
	int ret = 0, timeout;
	struct iw_scan_req req;
	const u8 *ssid = params->ssids[0].ssid;
	size_t ssid_len = params->ssids[0].ssid_len;
	struct wlreq_set_appie * app_ie;
	u8 buf[512];
	u8 bcAddr1[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (ssid_len > IW_ESSID_MAX_SIZE) {
		wpa_printf(MSG_DEBUG, "%s: too long SSID (%lu)",
			   __FUNCTION__, (unsigned long) ssid_len);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s extra IEs length: %d",
		   __FUNCTION__, params->extra_ies_len);

	app_ie = (struct wlreq_set_appie *)buf;
	app_ie->appBufLen = params->extra_ies_len;

	if (params->extra_ies_len) {
		wpa_hexdump(MSG_DEBUG,"extra ies", params->extra_ies, params->extra_ies_len);

		if (params->extra_ies != NULL) {
			memcpy(&(app_ie->appBuf[0]), params->extra_ies ,
			       app_ie->appBufLen);
			app_ie->appFrmType = WL_APPIE_FRAMETYPE_PROBE_REQUEST;
			set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
				     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) +
				     app_ie->appBufLen);

		}
	}

	marvell_commit(priv, drv->iface);
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

	if (ssid && ssid_len) {
		os_memset(&req, 0, sizeof(req));
		req.essid_len = ssid_len;
		req.bssid.sa_family = ARPHRD_ETHER;
		os_memset(req.bssid.sa_data, 0xff, ETH_ALEN);
		os_memcpy(req.essid, ssid, ssid_len);
		iwr.u.data.pointer = (caddr_t) &req;
		iwr.u.data.length = sizeof(req);
		iwr.u.data.flags = IW_SCAN_THIS_ESSID;
	} else {
		os_memset(&req, 0, sizeof(req));
		req.essid_len = 0;
		req.bssid.sa_family = ARPHRD_ETHER;
		os_memset(req.bssid.sa_data, 0xff, ETH_ALEN);
		iwr.u.data.pointer = (caddr_t) &req;
		iwr.u.data.length = sizeof(req);
	}

	if ((params->bssid != NULL) && ((os_memcmp(&bcAddr1[0], params->bssid, ETH_ALEN)) != 0)) {
		os_memcpy(&req.bssid.sa_data[0], params->bssid, ETH_ALEN);
	}

	if (ioctl(drv->ioctl_sock, SIOCSIWSCAN, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCSIWSCAN]: %s",
			   strerror(errno));
		ret = -1;
	}
	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	timeout = 10;

	eloop_cancel_timeout(marvell_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, marvell_scan_timeout, drv, drv->ctx);
	return ret;
}

__s32 marvell_freq_to_chnl(int freq) {
	__s32 chnl = 0;

	if ((2412<=freq) && (freq <= 2472)) {
		chnl = (freq - 2412)/5+1;
	} else if (freq == 2484) {
		chnl = 14;
	} else if (5180<=freq) {
		chnl = (freq - 5180)/5+36;
	}

	return chnl;
}

static int marvell_set_freq(void *priv, int freq) {
	struct marvell_driver_data *drv  = priv;
	struct iwreq iwr;
	int ret = 0;

	/* check if requested channel is the same as the current channel first */
	os_memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCGIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	if (iwr.u.freq.m == marvell_freq_to_chnl(freq))
		return 0;

	os_memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);
	iwr.u.freq.m = marvell_freq_to_chnl(freq);
	iwr.u.freq.e = 0;

	if (ioctl(drv->ioctl_sock, SIOCSIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);
	if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
		printf("ioctl[SIOCSIWCOMMIT]");
		return -1;
	}

	return ret;
}


static int
marvell_set_ssid(void *priv, const u8 *buf, int len) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;

	if (len > SSID_MAX_LEN)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;

	if (drv->we_version  < 21) {
		/* For historic reasons, set SSID length to include one extra
		 * character, C string nul termination, even though SSID is
		 * really an octet string that should not be presented as a C
		 * string. Some Linux drivers decrement the length by one and
		 * can thus end up missing the last octet of the SSID if the
		 * length is not incremented here. WE-21 changes this to
		 * explicitly require the length _not_ to include nul
		 * termination. */
		if (len)
			len++;
	}
	iwr.u.essid.length = len;

	if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		printf("len=%d\n", len);
		return -1;
	}
	return 0;
}

static int
marvell_set_bssid(void *priv, const u8 *buf) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;
	char *data_str = NULL;

	if (buf == NULL)
		return -1;

	data_str = os_malloc(IW_CUSTOM_MAX);
	memset(data_str, 0, sizeof(data_str));
	sprintf(data_str, "bssid %s", ether_sprintf(buf));

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = data_str;
	iwr.u.data.length = strlen(data_str);

	if (ioctl(drv->ioctl_sock, WL_IOCTL_SETCMD, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_SETCMD]");
		os_free(data_str);
		return -1;
	}

	os_free(data_str);
	return 0;
}

/*
 * Configure WPA parameters.
 */
static int
marvell_set_opt_ie(void *priv, const u8 *ie, size_t ie_len) {
	u8 buf[512];
	struct wlreq_set_appie * app_ie;

	if (!ie || !ie_len)
		return 1;
	
	app_ie = (struct wlreq_set_appie *)buf;
	app_ie->appBufLen = ie_len;

	memcpy(&(app_ie->appBuf[0]), ie , ie_len);

	app_ie->appFrmType = WL_OPTIE_ASSOC_INCL_RSN;
	set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
		     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) + app_ie->appBufLen);
	
	wpa_hexdump(MSG_DEBUG,"Set RSNE", ie, ie_len);	
	
	return 0;
}
 
static int
marvell_configure_wpa(struct marvell_driver_data *drv, struct wpa_driver_associate_params *params) {
	u8 wpawpa2mode;
	char ciphersuite[24];

	if ((params->wpa_proto & WPA_PROTO_WPA) &&
			!(params->wpa_proto & WPA_PROTO_RSN) &&
			(params->key_mgmt_suite & WPA_KEY_MGMT_PSK))
		wpawpa2mode = 0x81;
	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
			!(params->wpa_proto & WPA_PROTO_WPA) &&
			((params->key_mgmt_suite & WPA_KEY_MGMT_PSK) ||
			 (params->key_mgmt_suite & WPA_KEY_MGMT_PSK_SHA256)||
			 (params->key_mgmt_suite & WPA_KEY_MGMT_FT_PSK)))
		wpawpa2mode = 0x82;
	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
			(params->wpa_proto & WPA_PROTO_WPA) &&
			(params->key_mgmt_suite & WPA_KEY_MGMT_PSK))
		wpawpa2mode = 0x83;
	else if ((params->wpa_proto & WPA_PROTO_WPA) &&
			!(params->wpa_proto & WPA_PROTO_RSN) &&
			(params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X))
		wpawpa2mode = 0x84;
	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
			!(params->wpa_proto & WPA_PROTO_WPA) &&
			((params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X)||
			 (params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X_SHA256)))
		wpawpa2mode = 0x85;
	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
			(params->wpa_proto & WPA_PROTO_WPA) &&
			(params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X))
		wpawpa2mode = 0x86;
    else if ((params->wpa_proto & WPA_PROTO_RSN) &&
            (params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X_SUITE_B))
        wpawpa2mode = 0x87;
    else if ((params->wpa_proto & WPA_PROTO_RSN) &&
            (params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192))
        wpawpa2mode = 0x88;
    else if (params->key_mgmt_suite & WPA_KEY_MGMT_WPS)
        wpawpa2mode = 0x10;
	else
		wpawpa2mode = 0;

	
	if (set80211param(drv, WL_PARAM_WPAWPA2MODE, wpawpa2mode,TRUE)) {
		wpa_printf(MSG_DEBUG,"%s: Mode %x setting failed", __func__,
			   wpawpa2mode);
		return -1;
	}
	
   	if ((params->wpa_proto & WPA_PROTO_WPA) &&
       	(params->pairwise_suite & WPA_CIPHER_TKIP))
       	strcpy(ciphersuite, "wpa tkip");        
   	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
       	(params->pairwise_suite & WPA_CIPHER_CCMP))
       	strcpy(ciphersuite, "wpa2 aes-ccmp");
    else if ((params->wpa_proto & WPA_PROTO_RSN) &&
   	    (params->pairwise_suite & WPA_CIPHER_GCMP))
        strcpy(ciphersuite, "wpa2 aes-gcmp");
    else if ((params->wpa_proto & WPA_PROTO_RSN) &&
   	    (params->pairwise_suite & WPA_CIPHER_CCMP_256))
        strcpy(ciphersuite, "wpa2 aes-ccmp-256");
    else if ((params->wpa_proto & WPA_PROTO_RSN) &&
   	    (params->pairwise_suite & WPA_CIPHER_GCMP_256))
		strcpy(ciphersuite, "wpa2 aes-gcmp-256");
   	else if ((params->wpa_proto & WPA_PROTO_RSN) &&
       	(params->pairwise_suite & WPA_CIPHER_TKIP))
       	strcpy(ciphersuite, "wpa2 tkip");        
   	else if ((params->wpa_proto & WPA_PROTO_WPA) &&
       	(params->pairwise_suite & WPA_CIPHER_CCMP))
       	strcpy(ciphersuite, "wpa aes-ccmp");

	wpa_printf(MSG_DEBUG,"%s\n", ciphersuite);
#if 1
    if (params->key_mgmt_suite & WPA_KEY_MGMT_WPS){
        wpa_printf(MSG_DEBUG,"%s:configured mode=%x cipher suite=%s proto %d suite %d wpa_ie=%lp wpa_ie_len=%d", __func__,
               wpawpa2mode,ciphersuite, params->wpa_proto, params->pairwise_suite,
               params->wpa_ie, params->wpa_ie_len);
        return 0;
    }
	if (set80211priv(drv, WL_IOCTL_SET_CIPHERSUITE, &ciphersuite,
			 sizeof(ciphersuite))) {
		wpa_printf(MSG_DEBUG,"%s: Cipher Suite %s setting failed",
			   __func__,ciphersuite);
		return -1;
	}
#endif
	wpa_printf(MSG_DEBUG,"%s:configured mode=%x cipher suite=%s proto %d suite %d wpa_ie=%lp wpa_ie_len=%d", __func__,
		   wpawpa2mode,ciphersuite, params->wpa_proto, params->pairwise_suite,
		   params->wpa_ie, params->wpa_ie_len);
		   
	if (wpawpa2mode)
	{
		marvell_set_opt_ie(drv, params->wpa_ie, params->wpa_ie_len);
	}

	return 0;
}

#ifdef CONFIG_MULTI_AP
static int
marvell_set_multiap(void *priv, const u8 value) {
	struct marvell_driver_data *drv = priv;
	struct iwreq iwr;
	char *data_str = NULL;

	data_str = os_malloc(IW_CUSTOM_MAX);
	memset(data_str, 0, sizeof(data_str));
	sprintf(data_str, "multiap %d", value);

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = data_str;
	iwr.u.data.length = strlen(data_str);

	if (ioctl(drv->ioctl_sock, WL_IOCTL_SETCMD, &iwr) < 0)
		perror("ioctl[WL_IOCTL_SETCMD]");

	os_free(data_str);
	return 0;
}

static u8
marvell_get_multiap(void *priv) {
	struct marvell_driver_data *drv = (struct marvell_driver_data *)priv;
    	u8 buf[256];
    	u8 len = 0;
    	u8 *pos = NULL;
    	memset(buf, 0, sizeof(buf));
    	memcpy(buf, "multiap", strlen("multiap"));

    	len = get80211priv(drv, WL_IOCTL_GETCMD, buf, sizeof(buf));
    	if (len <= 0)
    		return 0;
    	
    	buf[len] = '\0';
    	pos = strstr(buf, "multiap:");
	if (pos == NULL)
		return 0;
	pos += strlen("multiap:");
    	return atoi(pos);
}
#endif /* CONFIG_MULTI_AP */

static int
marvell_deauth(void *priv, const const u8 *addr, int reason_code) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_mlme mlme;
	int ret;
	wpa_printf(MSG_DEBUG,
		   "%s: addr=%s reason_code=%d\n",
		   __func__, ether_sprintf(addr), reason_code);

	mlme.im_op = WL_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = set80211param(drv, WL_PARAM_MLME_REQ, (int)&mlme,FALSE);

	drv->assoc_freq = 0;
	memset(drv->bssid, 0, ETH_ALEN);
	return ret;
}

static int
marvell_associate(void *priv,
		  struct wpa_driver_associate_params *params) {
	struct marvell_driver_data *drv = priv;
	int ret = 0;
	if ((params->pairwise_suite != WPA_CIPHER_NONE) &&
			(params->key_mgmt_suite != WPA_KEY_MGMT_NONE)&&
			marvell_configure_wpa(drv, params) < 0)
		ret = -1;
	if (params->key_mgmt_suite == WPA_KEY_MGMT_WPS)
		marvell_configure_wpa(drv, params);    
	if (params->freq.freq &&
			marvell_set_freq(drv, params->freq.freq) < 0) {
		ret = -1;
	} else {
		drv->assoc_freq = params->freq.freq;
	}
	marvell_commit(priv, drv->master_iface);
	if (marvell_set_ssid(drv, params->ssid, params->ssid_len) < 0) {
		ret = -1;
	} else {
		ret = 0;
	}
	if (params->bssid && marvell_set_bssid(drv, params->bssid) < 0) {
		ret = -1;
	} else {
		ret = 0;
	}
//#ifdef CONFIG_MULTI_AP
//	marvell_set_multiap(drv, (params->multi_ap) ? MAP_ATTRIBUTE_BACKHAUL_STA : 0);
//#endif /* CONFIG_MULTI_AP */
	marvell_commit(priv, drv->iface);
	return ret;
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len) {
	struct marvell_driver_data *drv = (struct marvell_driver_data *)ctx;

	drv_event_eapol_rx(drv->ctx, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));

}

static void *
marvell_init(void *ctx, const char *ifname) {
	struct marvell_driver_data *drv;
	struct ifreq ifr;
	char brname[IFNAMSIZ];

	drv = os_zalloc(sizeof(struct marvell_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for marvell driver data\n");
		return NULL;
	}

	drv->ctx = ctx;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	memcpy(drv->iface, ifname, sizeof(drv->iface));

	strncpy(drv->master_iface, drv->iface, 5);
	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->ifindex = ifr.ifr_ifindex;

	os_strlcpy(ifr.ifr_name, drv->master_iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->master_ifindex = ifr.ifr_ifindex;

	if (!linux_iface_up(drv->ioctl_sock, drv->iface))
		linux_set_iface_flags(drv->ioctl_sock, drv->iface, 1);

	if (marvell_wireless_event_init(drv))
		goto bad;
	return drv;

bad:

	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv != NULL)
		free(drv);
	return NULL;
}


static void
marvell_deinit(void* priv) {
	struct marvell_driver_data *drv = priv;
	const u8 ssid_buf[5];
	int ssid_len;
	struct wlreq_set_appie *app_ie;
	u8 buf[512];

	strncpy(ssid_buf, "", 5);
	if (marvell_set_ssid(drv, ssid_buf, ssid_len) < 0) {
		wpa_printf(MSG_DEBUG, "Clear essid fail\n");
	}

	app_ie = (struct wlreq_set_appie *)buf;
	app_ie->appBufLen = 0;

	app_ie->appFrmType = WL_APPIE_FRAMETYPE_PROBE_REQUEST;
	set80211priv(priv, WL_IOCTL_SET_APPIE, app_ie,
		     sizeof(app_ie->appFrmType) + sizeof(app_ie->appBufLen) +
		     app_ie->appBufLen);

	marvell_commit(priv, drv->iface);

	netlink_deinit(drv->netlink);
	(void) linux_set_iface_flags(drv->ioctl_sock, drv->iface, 0);

	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	free(drv);
	return;
}

static int marvell_remain_on_channel(void *priv, unsigned int freq,
				     unsigned int duration) {
	struct i802_bss *bss = priv;

	marvell_set_freq(priv,freq);

	wpa_printf(MSG_DEBUG, "Marvell: request remain-on-channel "
		   "(freq=%d duration=%u)", freq, duration);
	return 0;
}

#ifdef CONFIG_WLS_PF
/* Send wlsetcmd with TLV data to driver. Use vendor_id as TLV ID and subcmd as TLV length*/
static int marvell_vendor_cmd(void *priv, unsigned int vendor_id,
			      unsigned int subcmd, const u8 *data, size_t data_len,
			      struct wpabuf *buf) {
	char *data_str = NULL, *pos, *end;
	struct marvell_driver_data *drv = priv;
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)drv->ctx;
	struct wpa_bss * bss;
	struct iwreq iwr;
	size_t str_len = 5 + 5 + data_len * 3 + 1; /* type + length + tlv */
	u16 tlv_type = vendor_id;
	u16 tlv_len = subcmd;
	u8 ap_addr[ETH_ALEN];
	int ret, i;

	memcpy(ap_addr, data, ETH_ALEN);
	bss = wpa_bss_get_bssid(wpa_s, ap_addr);
	if (bss == NULL) {
		wpa_printf(MSG_ERROR, "can't find the AP with mac address" MACSTR
			   "in scan result\n", MAC2STR(ap_addr));
		return -1;
	}
	data_str = os_malloc(str_len);
	pos = data_str;
	end = pos + str_len;
	ret = os_snprintf(pos, str_len, "tlv ");
	pos += ret;
	ret = os_snprintf(pos, end - pos, "%d ", tlv_type);
	pos += ret;
	ret = os_snprintf(pos, end - pos, "%d ", tlv_len);
	pos += ret;

	//wpa_snprintf_hex(pos, end - pos, data,data_len);
	for (i = 0 ; i < data_len; i++) {
		ret = os_snprintf(pos, end - pos, "%02x ", data[i]);
		pos += ret;
	}
	wpa_printf(MSG_DEBUG,"set TLV command %s\n", data_str);

	wpa_printf(MSG_DEBUG,"set freq to %d\n", bss->freq);

	if (bss->freq) {
		if (marvell_set_freq(drv, bss->freq) < 0) {
			wpa_printf(MSG_ERROR,"set freq fail\n");
			return -1;
		}
	} else {
		wpa_printf(MSG_ERROR,"No freq info in this BSS entry\n");
		return -1;
	}
	os_memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->master_iface, IFNAMSIZ);
	iwr.u.data.pointer = data_str;
	iwr.u.data.length = strlen(data_str);

	if (ioctl(drv->ioctl_sock, WL_IOCTL_SETCMD, &iwr) < 0) {
		perror("ioctl[WL_IOCTL_SETCMD]");
		return -1;
	}

	return 0;
}
#endif

struct hostapd_hw_modes *
			marvell_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags) {
	static struct hostapd_hw_modes *mrvl_hw_mode;
	static struct hostapd_channel_data *mrvl_5g_channel;
	static struct hostapd_channel_data *mrvl_24g_channel;
	struct hostapd_channel_data *channel;
	int chidx = 0, i;
	*num_modes = 2;
	*flags = 0;

	mrvl_hw_mode = os_zalloc(*num_modes * sizeof(struct hostapd_hw_modes));
	mrvl_5g_channel = os_zalloc(25 * sizeof(struct hostapd_channel_data));
	mrvl_24g_channel = os_zalloc(13 * sizeof(struct hostapd_channel_data));

	mrvl_hw_mode[1].mode = HOSTAPD_MODE_IEEE80211A;
	channel = mrvl_5g_channel;

	memset(channel, 0, 25 * sizeof(struct hostapd_channel_data));

	for (i = 0; i < 8; i++, chidx++) {
		channel[chidx].chan = 36 + i * 4;
		channel[chidx].freq = 5180 + i * 20;
	}

	for (i = 0; i < 12; i++, chidx++) {
		channel[chidx].chan = 100 + i * 4;
		channel[chidx].freq = 5500 + i * 20;
	}

	for (i = 0; i < 5; i++, chidx++) {
		channel[chidx].chan = 149 + i * 4;
		channel[chidx].freq = 5745 + i * 20;
	}

	mrvl_hw_mode[1].channels = mrvl_5g_channel;
	mrvl_hw_mode[1].num_channels = 25;

	mrvl_hw_mode[0].mode = HOSTAPD_MODE_IEEE80211G;
	channel = mrvl_24g_channel;

	memset(channel, 0, 13 * sizeof(struct hostapd_channel_data));
	chidx = 0;

	for (i = 0; i < 13; i++, chidx++) {
		channel[chidx].chan = i;
		channel[chidx].freq = 2412 + i * 5;
	}


	mrvl_hw_mode[0].channels = mrvl_24g_channel;
	mrvl_hw_mode[0].num_channels = 13;

	return mrvl_hw_mode;
}

static int
marvell_del_key(void *priv, const u8 *addr, int key_idx) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_del_key wk;
	int ret;

	wpa_printf(MSG_DEBUG,"%s: addr=%s key_idx=%d",
		   __func__, ether_sprintf(addr), key_idx);

	memset(&wk, 0, sizeof(wk));
	if (addr != NULL) {
		memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (u8) WL_KEYIX_NONE;
	} else {
		wk.idk_keyix = key_idx;
	}
	ret = set80211param(drv, WL_PARAM_DELKEYS, (int)&wk,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to delete key (addr %s"
			   " key_idx %d)", __func__, ether_sprintf(addr),
			   key_idx);
	}

	return ret;
}

static int
marvell_set_key(const char *ifname,void *priv, enum wpa_alg alg,
		const u8 *addr, int key_idx, int set_tx, const u8 *seq,
		size_t seq_len, const u8 *key, size_t key_len) {
	struct marvell_driver_data *drv = priv;
	struct wlreq_key wk;
	u_int8_t cipher;
	int ret;

	if (alg == WPA_ALG_NONE)
		return marvell_del_key(priv, addr, key_idx);

	wpa_printf(MSG_DEBUG,
		   "%s: alg=%d addr=%s key_idx=%d\n",
		   __func__, alg, ether_sprintf(addr), key_idx);

	switch (alg) {
	case WPA_ALG_WEP:
		cipher = WL_CIPHER_WEP104;
		break;
	case WPA_ALG_TKIP:
		cipher = WL_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		cipher = WL_CIPHER_CCMP;
		break;
	case WPA_ALG_IGTK:
		cipher = WL_CIPHER_IGTK;
		break;
	case WPA_ALG_CCMP_256:
		cipher = WL_CIPHER_CCMP_256;
		break;
	case WPA_ALG_GCMP:
		cipher = WL_CIPHER_GCMP;
		break;
	case WPA_ALG_GCMP_256:
		cipher = WL_CIPHER_GCMP_256;
		break;
	case WPA_ALG_BIP_CMAC_256:   
		cipher = WL_CIPHER_AES_CMAC_256;
		break;
	case WPA_ALG_BIP_GMAC_128:  
		cipher = WL_CIPHER_AES_GMAC;
		break;
	case WPA_ALG_BIP_GMAC_256:  
		cipher = WL_CIPHER_AES_GMAC_256;
		break;
	default:
		printf("%s: unknown/unsupported algorithm %d\n",
		       __func__, alg);
		return -1;
	}

	if (key_len > sizeof(wk.ik_keydata)) {
		printf("%s: key length %lu too big\n", __func__,
		       (unsigned long) key_len);
		return -3;
	}

	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = WL_KEY_RECV | WL_KEY_XMIT;
	if (addr == NULL || is_broadcast_ether_addr(addr)) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = key_idx;
		wk.ik_flags |= WL_KEY_DEFAULT;
	} else {
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = WL_KEYIX_NONE;
	}
	wk.ik_keylen = key_len;
	memcpy(wk.ik_keydata, key, key_len);
	memcpy(wk.ik_pn, seq, seq_len);
	memcpy(&wk.ik_keytsc, seq, seq_len);

	ret = set80211param(drv, WL_PARAM_SETKEYS, (int)&wk,FALSE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to set key (addr %s"
			   " key_idx %d alg '%d' key_len %lu txkey %d)",
			   __func__, ether_sprintf(wk.ik_macaddr), key_idx,
			   alg, (unsigned long) key_len, set_tx);
	}

	return ret;
}

static int marvell_set_operstate(void *priv, int state) {
	struct marvell_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "Marvell: Set %s operstate %d->%d (%s)",
		   drv->iface, drv->operstate, state,
		   state ? "UP" : "DORMANT");
	drv->operstate = state;
	return 0;
}

const struct wpa_driver_ops wpa_driver_marvell_ops = {
	.name			   = "marvell",
	.desc                      = "Marvell 802.11 STA interface support",
	.init                      = marvell_init,
	.deinit                    = marvell_deinit,
	.get_bssid                 = marvell_get_bssid,
	.get_ssid                  = marvell_get_ssid,
	.set_countermeasures       = marvell_set_countermeasures,
	.deauthenticate            = marvell_deauth,
	.associate                 = marvell_associate,
	.get_scan_results2         = marvell_get_scan_results,
	.scan2                     = marvell_scan,
	.send_action		   = marvell_send_action,
	.commit                    = marvell_commit,
	.remain_on_channel         = marvell_remain_on_channel,
#ifdef CONFIG_WLS_PF
	.vendor_cmd		   = marvell_vendor_cmd,
#endif
	.get_hw_feature_data	   = marvell_get_hw_feature_data,
	.set_key		   = marvell_set_key,
	.set_operstate		   = marvell_set_operstate,
#ifdef CONFIG_MULTI_AP
	.get_mapmode		   = marvell_get_multiap,
#endif /* CONFIG_MULTI_AP */
};
#endif
