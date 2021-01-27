/** @file ap8xLnxSwMimoTypes.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
  *
  * NXP CONFIDENTIAL
  * The source code contained or described herein and all documents related to
  * the source code ("Materials") are owned by NXP, its
  * suppliers and/or its licensors. Title to the Materials remains with NXP,
  * its suppliers and/or its licensors. The Materials contain
  * trade secrets and proprietary and confidential information of NXP, its
  * suppliers and/or its licensors. The Materials are protected by worldwide copyright
  * and trade secret laws and treaty provisions. No part of the Materials may be
  * used, copied, reproduced, modified, published, uploaded, posted,
  * transmitted, distributed, or disclosed in any way without NXP's prior
  * express written permission.
  *
  * No license under any patent, copyright, trade secret or other intellectual
  * property right is granted to or conferred upon you by disclosure or delivery
  * of the Materials, either expressly, by implication, inducement, estoppel or
  * otherwise. Any license under such intellectual property rights must be
  * express and approved by NXP in writing.
  *
  */

//
//  newdp_shared.h
//
//  This file provides definitions that are shared between radio FW Data plane,
//  and Host driver. Some of these are Hardware (Chip Rev) centric, and will be
//  noted, and others are shared Software structures or constants affecting the
//  interface.
//
//

#ifndef AP8X_SW_MIMO_TYPES_H_
#define AP8X_SW_MIMO_TYPES_H_

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long s64;
typedef int s32;
typedef short s16;
typedef signed char s8;

// VHT
typedef struct mimo_ctrl_field_ac {
	u32 NcIdx:3;
	u32 NrIdx:3;
	u32 ChanWidth:2;
	u32 Ng:2;
	u32 CodeBook:1;
	u32 FbType:1;
	u32 RemSeg:3;
	u32 FstSeg:1;
	u32 rsvd1:2;
	u32 token:6;
	u32 rsvd2:8;
	u32 rsvd3:28;
} mimo_ctrl_field_t;

// HE
typedef struct mimo_ctrl_field_ax {
	u32 NcIdx:3;
	u32 NrIdx:3;
	u32 ChanWidth:2;
	u32 Grouping:1;
	u32 CodeBook:1;
	u32 FbType:2;
	u32 RemSeg:3;
	u32 FstSeg:1;
	u32 RuStartdIdx:7;
	u32 RuEndIdx:7;
	u32 DialogToken:6;
	u32 SubchBitmapPres:1;
	u32 rsvd1:3;
	u32 SubchBitmap:8;
	u32 rsvd2:12;
} mimo_ctrl_field_ax_t;

// HE
typedef struct mimo_ctrl_field_cm {
	u32 NcIdx:3;
	u32 NrIdx:3;
	u32 ChanWidth:2;
	u32 reserved0:24;
	u32 reserved1:24;
} mimo_ctrl_field_cm_t;

// new structure, needs to include the following info

typedef struct {
	u32 addrPtr;		// currently offset in bytes
	u32 size;		///< Used size
} mu_mem_t;

typedef struct {
	u8 Num_Users;
	u8 muGID;
	u8 Pkttype;
	u8 Reserved1;
	/*
	   u32             Nr:4;
	   u32             Nc:4;
	   u32             Ng:2;
	   u32             Val_BW:4;
	   u32             Pkttype:3;
	   u32             muGID:6;
	   u32             Reserved1:1;
	   u32             Num_Users:8;

	   u8                           NcArray[8];
	   //u8              User_MAC_Array[8][6];
	   mu_mem_t        User_Feedback_Array[8];
	   mu_mem_t             SBF_out;
	 */
} mu_config_t;

typedef struct {
	// DW0
	u32 Source:3;
	u32 Cp:1;
	u32 Cdbk:2;
	u32 Nr:4;
	u32 Nc:4;
	u32 Ng:2;
	u32 Bw:4;
	u32 Pktype:3;
	u32 MU:1;
	u32 Nc1:3;
	u32 Nc2:3;
	u32 Resv:2;
	// DW1
	u32 Nc3:3;
	u32 Nc4:3;
	u32 Nc5:3;
	u32 Nc6:3;
	u32 Nc7:3;
	u32 Nc8:3;
	u32 DWNumber:14;
	// DW2
	u32 SNRnc1:8;
	u32 SNRnc2:8;
	u32 SNRnc3:8;
	u32 SNRnc4:8;
	// DW3
	u32 SNRnc5:8;
	u32 SNRnc6:8;
	u32 SNRnc7:8;
	u32 SNRnc8:8;
} mu_bf_header_t;
#endif /* AP8X_SW_MIMO_TYPES_H_ */
