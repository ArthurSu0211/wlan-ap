/** @file ap8xLnxSwMimo.h
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
#ifndef AP8X_SW_MIMO_H_
#define AP8X_SW_MIMO_H_

#define FEEDBACK_SIZE_1S 896	// = 256*2*7/4 80 MHz 8x1, VHT
#define FEEDBACK_SIZE_2S 1664	// = 256*2*(7+6)/4 80 MHz 8x2, VHT
#define FEEDBACK_SIZE_3S 2304	// = 256*2*(7+6+5)/4 80 MHz 8x3, VHT
#define FEEDBACK_SIZE_4S 2816	// = 256*2*(7+6+5+4)/4 80 MHz 8x4, VHT

int createDspData(unsigned char *bufferPtr, u8 muGID, u8 numUsers,
		  u8 pktTypeIn);

#endif /* AP8X_SW_MIMO_H_ */
