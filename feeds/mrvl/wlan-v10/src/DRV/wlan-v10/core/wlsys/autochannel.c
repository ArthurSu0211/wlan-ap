/** @file autochannel.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
  *
  * This software file (the "File") is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

/*
 *
 * Purpose:
 *    This file contains the implementations of the auto channel selection functions.
 *
 */
#include "ap8xLnxRegs.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxVer.h"

#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "util.h"

#include "osif.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlmac.h"

#include "wl_macros.h"
#include "wldebug.h"
#include "StaDb.h"
#include "domain.h"
#include "macMgmtMlme.h"
#ifdef CFG80211
#include "cfg80211.h"
#endif
#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#ifdef AUTOCHANNEL

void SendScanCmd(vmacApInfo_t * vmacSta_p, UINT8 * channels);
void StopAutoChannel(vmacApInfo_t * vmacSta_p);
UINT32
Rx_Traffic_Cnt(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_TRAFFIC_CNT);
#endif
}

UINT32
Rx_Traffic_Err_Cnt(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_TRAFFIC_ERR_CNT);
#endif
}

UINT32
Rx_Traffic_BBU(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_BBU_RXRDY_CNT);
#endif
}

static void
PrepareNextScan(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->autochannelstarted = 0;
}

static BOOLEAN
SetupScan(vmacApInfo_t * vmacAP_p)
{
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	UINT8 *mib_autochannel_p;

#ifdef COEXIST_20_40_SUPPORT
	UINT8 ScanningFlag = 0;
#endif
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	struct net_device *netdev = NULL;
	struct wlprivate *wlpptr = NULL;
	BOOLEAN vmacSTA_UP = 0;
	int i = 0, j;

	if (vmacAP_p->master)
		vmacSta_p = vmacAP_p->master;
	else
		vmacSta_p = vmacAP_p;
	mib = vmacSta_p->ShadowMib802dot11;
	mib_autochannel_p = mib->mib_autochannel;
	PhyDSSSTable = mib->PhyDSSSTable;

	netdev = vmacSta_p->dev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	vmacSta_p->preautochannelfinished = 0;
	vmacSta_p->acs_cur_bcn = 0;

	while (i <= bss_num) {
		//find the STA wdevxsta0 device here.
		if (wlpptr->vdev[i]) {
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->
			    vmacSta_p->OpMode == WL_OP_MODE_VSTA) {
				if (wlpptr->wlpd_p->dev_running[i]) {	//interface used to be UP and running
					vmacSTA_UP = 1;
					break;
				}
			}
		}
		i++;
	}
#ifdef COEXIST_20_40_SUPPORT
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) &&
	    ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)))
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_BandN ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_GandN ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_BandGandN
		    || *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_11AC_MIXED
#ifdef SOC_W906X
		    || *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_Nand11AX ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_11AX_MIXED
#endif /* SOC_W906X */
			) {
			/** only do 20/40 coexist for n mode in 2.4G band **/
			void Disable_StartCoexisTimer(vmacApInfo_t * vmacSta_p);

			*(mib->USER_ChnlWidth) = 1;
			ScanningFlag = 1;

		}
#endif

#ifdef CLIENT_SUPPORT
#ifdef COEXIST_20_40_SUPPORT
	if ((*mib_autochannel_p || ScanningFlag) && (!vmacSta_p->busyScanning)
	    && ((*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) || (!vmacSTA_UP)))
#else
	if (*mib_autochannel_p && (!vmacSta_p->busyScanning) &&
	    ((*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) || (!vmacSTA_UP)))
#endif
#else
	if (*mib_autochannel_p && !vmacSta_p->busyScanning)
#endif
	{
		UINT8 scanChannel[IEEEtypes_MAX_CHANNELS +
				  IEEEtypes_MAX_CHANNELS_A] =
			{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 36, 40,
44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0 };
		if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
			UINT8 i;

			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				if (scanChannel[i] == 165) {
					break;
				}
			}

			if ((i + 4) >=
			    (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A))
				return FALSE;

			scanChannel[i + 1] = 169;
			scanChannel[i + 2] = 173;
			scanChannel[i + 3] = 177;
			scanChannel[i + 4] = 181;

		}
		/* get range to scan */
		domainGetInfo(scanChannel);
		if (*(vmacSta_p->Mib802dot11->mib_autochannel) == 2) {
			memset(scanChannel, 0,
			       sizeof(UINT8) * (IEEEtypes_MAX_CHANNELS +
						IEEEtypes_MAX_CHANNELS_A));
			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				for (j = 0;
				     j <
				     (IEEEtypes_MAX_CHANNELS +
				      IEEEtypes_MAX_CHANNELS_A); j++) {
					if (vmacSta_p->ChannelList[i] ==
					    vmacSta_p->OpChanList[j]) {
						scanChannel[i] =
							vmacSta_p->
							ChannelList[i];
						break;
					}
				}
			}
		}
		if (PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH) {
			UINT8 i;

			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
					if (scanChannel[i] == 181) {
						scanChannel[i] = 0;
					}
				} else {
					if (scanChannel[i] >= 165) {
						scanChannel[i] = 0;
					}
				}
			}
		}
#ifdef EXCLUDE_DFS_CHANNEL
		if (*(vmacSta_p->Mib802dot11->mib_autochannel) != 2) {
			UINT8 i, j = 0;
			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				switch (*(mib->mib_regionCode)) {
				case DOMAIN_CODE_ETSI:	// select 36, 40, 44, 48
					if (scanChannel[i] >= 52) {
						scanChannel[i] = 0;
					}
					break;
				default:	// select 36,40,44,48,   149,153,157,161
					if (scanChannel[i] >= 52 &&
					    scanChannel[i] <= 144) {
						scanChannel[i] = 0;
					}
				}
			}
			// Reorganize the channel list
			for (i = 0; (i < IEEEtypes_MAX_CHANNELS_A); i++) {
				if ((j == 0) &&
				    (scanChannel[i + IEEEtypes_MAX_CHANNELS] ==
				     0)) {
					j = i + IEEEtypes_MAX_CHANNELS;
				}
				if ((j != 0) &&
				    (scanChannel[i + IEEEtypes_MAX_CHANNELS] !=
				     0)) {
					// Move the channel id
					scanChannel[j++] =
						scanChannel[i +
							    IEEEtypes_MAX_CHANNELS];
					scanChannel[i +
						    IEEEtypes_MAX_CHANNELS] = 0;
				}
			}
		}
#endif //EXCLUDE_DFS_CHANNEL
		SendScanCmd(vmacSta_p, scanChannel);
		return TRUE;
	}
#ifdef SOC_W8964
	wlSetOpModeMCU(vmacSta_p, MCU_MODE_AP);
#endif
	if (*mib_autochannel_p == 0)
		return FALSE;
	return TRUE;
}

#ifdef SOC_W8964
extern BOOLEAN
wlSetOpModeMCU(vmacApInfo_t * vmacSta_p, UINT32 mode)
{
	switch (mode) {
	case MCU_MODE_AP:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE, WL_AP_MODE);
		break;
	case MCU_MODE_STA_INFRA:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE, WL_STA_MODE);
		break;
	case MCU_MODE_STA_ADHOC:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE,
			       (UINT32) (WL_IBSS_MODE));
		break;
	default:
		return FALSE;
	}
	return TRUE;
}
#endif
extern BOOLEAN
wlUpdateAutoChan(vmacApInfo_t * vmacSta_p, UINT32 chan, UINT8 shadowMIB)
{
	MIB_802DOT11 *mib =
		shadowMIB ? vmacSta_p->ShadowMib802dot11 : vmacSta_p->
		Mib802dot11;

	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;
#ifdef CFG80211
	int i = 0;
	struct net_device *netdev = vmacSta_p->dev;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
#endif

#ifdef IEEE80211K
	MSAN_get_ACS_db(vmacSta_p, vmacSta_p->NumScanChannels, 0);
#endif /* IEEE80211K */

	PhyDSSSTable->CurrChan = chan;

	PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

	if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		switch (PhyDSSSTable->CurrChan) {
		case 1:
		case 2:
		case 3:
		case 4:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 5:
			/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
			/*if(*mib_extSubCh_p==0)
			   {
			   if(domainChannelValid(chan+4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   else if(domainChannelValid(chan-4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   }
			   else if(*mib_extSubCh_p==1)
			   {
			   if(domainChannelValid(chan-4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   else
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   }
			   else if(*mib_extSubCh_p==2)
			   {
			   if(domainChannelValid(chan+4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   else
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   }
			   break; */
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
			if (*mib_extSubCh_p == 0) {
				if (domainChannelValid
				    (chan - 4, FREQ_BAND_2DOT4GHZ))
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (domainChannelValid
					 (chan + 4, FREQ_BAND_2DOT4GHZ))
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
			} else if (*mib_extSubCh_p == 1) {
				if (domainChannelValid
				    (chan - 4, FREQ_BAND_2DOT4GHZ))
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
			} else if (*mib_extSubCh_p == 2) {
				if (domainChannelValid
				    (chan + 4, FREQ_BAND_2DOT4GHZ))
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				else
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
			}
			break;
		case 11:
		case 12:
		case 13:
		case 14:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
			/* for 5G */
		case 36:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 40:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 44:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 48:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 52:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 56:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 60:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 64:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;

		case 100:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 104:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 108:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 112:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 116:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 120:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 124:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 128:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 132:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 136:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 140:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 144:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 149:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 153:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 157:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 161:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 165:
			if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
			}
			/* Channel 165 currently only supports 20 MHz BW. */
			/* Commented out for now.  Causes channel width to be set
			   to 20 MHz if current channel is 165 and then switched
			   to another channel. */
			/* PhyDSSSTable->Chanflag.ChnlWidth        = CH_20_MHz_WIDTH; */
			/* PhyDSSSTable->Chanflag.ExtChnlOffset = NO_EXT_CHANNEL; */
			break;
			if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
		case 68:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 72:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 76:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 80:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 84:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 88:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 92:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 96:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

		case 169:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 173:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 177:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 181:
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
				break;
		case 184:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 188:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 192:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 196:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			}

		default:
			break;
		}
	}
	if (PhyDSSSTable->CurrChan <= 14)
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
	else
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;

	if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ &&
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH ||
	     PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)) {
		int i;

		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (vmacSta_p->acs_db[i].channel !=
			    PhyDSSSTable->CurrChan)
				continue;
			if (!vmacSta_p->acs_db[i].ht40avail) {
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
			}
		}
	}

	vmacSta_p->preautochannelfinished = 1;
	ACS_start_timer(vmacSta_p);

#ifdef CFG80211
	if (PhyDSSSTable->CurrChan) {
		for (i = 0; i < bss_num; i++)
			mwl_send_vendor_acs_completed(priv->vdev[i],
						      PhyDSSSTable->CurrChan);
	}
#endif

	return TRUE;
}

extern BOOLEAN
wlSetRFChan(vmacApInfo_t * vmacSta_p, UINT32 channel)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	CHNL_FLAGS Chanflag;
	UINT8 retval;

	if (ACS_OpChanCheck(vmacSta_p, channel) == FAIL) {
		printk("autochannel is enabled and channel : %d is not in opreation channel list.\n", channel);
		return FALSE;
	}

	Chanflag = PhyDSSSTable->Chanflag;
	Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
	Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
	if (domainChannelValid
	    (channel, channel <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ)) {
		if (channel <= 14)
			Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
		else
			Chanflag.FreqBand = FREQ_BAND_5GHZ;
#ifdef SOC_W906X
		// TODO: check how to set the second channel for autochannel
		if (PhyDSSSTable->SecChan != 0 &&
		    PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
			/* swap primary and 2nd channel according to fw design */
			retval = wlchannelSet(vmacSta_p->dev,
					      PhyDSSSTable->SecChan, channel,
					      Chanflag, 1);
		} else {
			retval = wlchannelSet(vmacSta_p->dev, channel,
					      PhyDSSSTable->SecChan, Chanflag,
					      1);
		}
		if (retval != SUCCESS) {
#else
		if (wlchannelSet(vmacSta_p->dev, channel, Chanflag, 1)) {
#endif
			WLDBG_EXIT_INFO(DBG_LEVEL_15, "setting channel failed");
			return FALSE;
		}
	} else {
		printk("WARNNING: invalid channel %d for current domain\n",
		       (int)channel);
	}
	return TRUE;
}

void
scanControl(vmacApInfo_t * vmacSta_p)
{
#ifdef MRVL_DFS
	if ((!channelSelected
	     (vmacSta_p,
	      ((*(vmacSta_p->Mib802dot11->mib_ApMode)) & AP_MODE_BAND_MASK) >=
	      AP_MODE_A_ONLY))
	    && !vmacSta_p->dfsCacExp)
#else
	if (!channelSelected
	    (vmacSta_p,
	     ((*(vmacSta_p->Mib802dot11->mib_ApMode)) & AP_MODE_BAND_MASK) >=
	     AP_MODE_A_ONLY))
#endif
	{
		if (SetupScan(vmacSta_p))
			return;
	} else {
		PrepareNextScan(vmacSta_p);
	}
#ifdef MRVL_DFS
	vmacSta_p->dfsCacExp = 0;
#endif
	extStaDb_ProcessKeepAliveTimerInit(vmacSta_p);
	MonitorTimerInit(vmacSta_p);
}

#ifndef IEEE80211_DH
BOOLEAN
UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p, UINT32 channel)
{
	extern BOOLEAN force_5G_channel;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;

	if (domainChannelValid
	    (channel,
	     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
						  14 ? FREQ_BAND_2DOT4GHZ :
						  FREQ_BAND_5GHZ))) {
		PhyDSSSTable->CurrChan = channel;

		/* Currentlly, 40M is not supported for channel 14 */
		if (PhyDSSSTable->CurrChan == 14) {
			if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
			    || (PhyDSSSTable->Chanflag.ChnlWidth ==
				CH_40_MHz_WIDTH) ||
			    (PhyDSSSTable->Chanflag.ChnlWidth ==
			     CH_80_MHz_WIDTH) ||
			    (PhyDSSSTable->Chanflag.ChnlWidth ==
			     CH_160_MHz_WIDTH))
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
		}
		//PhyDSSSTable->Chanflag.ChnlWidth=CH_40_MHz_WIDTH;
		PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
		if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH))) {
			switch (PhyDSSSTable->CurrChan) {
			case 1:
			case 2:
			case 3:
			case 4:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 5:
				if (*mib_extSubCh_p == 0)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				else if (*mib_extSubCh_p == 1)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 2)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				break;
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
				if (*mib_extSubCh_p == 0)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 1)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 2)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
				/* for 5G */
			case 36:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 40:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 44:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 48:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 52:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 56:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 60:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 64:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 68:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 72:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 76:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 80:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 84:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 88:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 92:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 96:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 100:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 104:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 108:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 112:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 116:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 120:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 124:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 128:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 132:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 136:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 140:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 144:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 149:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 153:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 157:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 161:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 165:
				if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				} else {
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				}
				break;
			case 169:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 173:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 177:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 181:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
				break;

			case 184:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 188:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 192:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 196:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			default:
				break;
			}
		}
		if (force_5G_channel) {
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
		} else {
			if (PhyDSSSTable->CurrChan <= 14)
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_2DOT4GHZ;
			else
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_5GHZ;
		}
	} else {
		WLDBG_INFO(DBG_LEVEL_15, "invalid channel %d\n", channel);
		return FALSE;
	}
	wlFwApplyChannelSettings(vmacSta_p->dev);
	return TRUE;
}
#endif //IEEE80211_DH

void
EnableBlockTrafficMode(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->StopTraffic = TRUE;
}

void
DisableBlockTrafficMode(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->StopTraffic = FALSE;
}

void
StopAutoChannel(vmacApInfo_t * vmacSta_p)
{
	void syncSrv_RestorePreScanSettings(vmacApInfo_t * vmacSta_p);
	UINT8 cur_channel;
	UINT8 *mib_autochannel_p =
		vmacSta_p->ShadowMib802dot11->mib_autochannel;

	if (vmacSta_p->busyScanning)
		syncSrv_RestorePreScanSettings(vmacSta_p);
	vmacSta_p->busyScanning = 0;
	if (*mib_autochannel_p) {
		/*Dont know why change vmacSta_p->autochannelstarted to be 1 here, but this prevent wdev0 doing autoscanning
		 * when stamode=6/7/8, and wdev0sta0 is down at the first commit. comment it out looks OK.
		 */
		//vmacSta_p->autochannelstarted = 1;

		/* Select channel and update when on parent interface only. Parent interface has master pointer as NULL
		 * In situation where wdev0 and wdev0ap0 are up; and then we use wdev0sta0 to do stascan, cur_channel could be assigned
		 * with 0 (5G) or 1 (2G). This is because ChanList[i] in virtual interface is 0. After that, any previously associated client
		 * to wdev0ap0 will fail to ping even if chan is set to 1 in 2G. 5G will fail because chan is set to 0, which is invalid.
		 */
		if (!vmacSta_p->master) {
			cur_channel =
				channelSelected(vmacSta_p,
						((*
						  (vmacSta_p->Mib802dot11->
						   mib_ApMode)) &
						 AP_MODE_BAND_MASK) >=
						AP_MODE_A_ONLY);

			if (cur_channel != 0)
				wlUpdateAutoChan(vmacSta_p, cur_channel, 0);
		}
		DisableBlockTrafficMode(vmacSta_p);
	}

	Disable_ScanTimerProcess(vmacSta_p);
	ACS_stop_timer(vmacSta_p);

	return;
}

UINT8
ACS_OpChanCheck(vmacApInfo_t * vmacSta_p, UINT8 channel)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT8 i;

	if (*(mib->mib_autochannel) == 2) {

		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
			if (channel == vmacSta_p->OpChanList[i]) {
				break;
			}
		}
		if (i == IEEE_80211_MAX_NUMBER_OF_CHANNELS) {
			return FAIL;
		}
	}
	return SUCCESS;
}

void
ACS_start_timer(vmacApInfo_t * vmacSta_p)
{
	ch_load_info_t *ch_load_p = &vmacSta_p->acs_cload;

	if (vmacSta_p->master != NULL) {
		return;
	}

	if (ch_load_p->started == 0) {
		TimerDisarm(&ch_load_p->timer);
		memset(ch_load_p, 0, sizeof(ch_load_info_t));
		ch_load_p->tag = CH_LOAD_ACS;
		ch_load_p->master = (UINT8 *) vmacSta_p;
		ch_load_p->dur = 500;
		ch_load_p->interval = 10000;
		ch_load_p->ignore_time = ((ch_load_p->interval + ch_load_p->dur) / 1000) + 1;	//ceil(ignore_time)
		ch_load_p->loop_count = 0;
		ch_load_p->callback = &wl_acs_ch_load_cb;
		ch_load_p->started = 1;
	}
	wl_get_ch_load_by_timer(ch_load_p);
}

void
ACS_stop_timer(vmacApInfo_t * vmacSta_p)
{
	ch_load_info_t *ch_load_p = &vmacSta_p->acs_cload;

	if (vmacSta_p->master != NULL) {
		return;
	}
	TimerDisarm(&ch_load_p->timer);
}
#endif
