/** @file ap8xLnxSwMimo.c
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

#include "ap8xLnxSwMimoTypes.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxSwMimo.h"

//#define FILE_INPUT
#ifdef FILE_INPUT
//#include "Matlab_Test_Rayleigh_Nt8_4users_1111_80MHz_Codebook1.h"
#include "Wireshark_2users2sts_SC5_2_SCBT_HE80_3.h"
#endif

#define DEFAULT_DIALOG_TOKEN 0x1f

unsigned short compressedInputSizes[4] =
	{ FEEDBACK_SIZE_1S, FEEDBACK_SIZE_2S, FEEDBACK_SIZE_3S,
FEEDBACK_SIZE_4S };

int
createDspData(unsigned char *bufferPtr, u8 muGID, u8 numUsers, u8 pktTypeIn)
{

	int size;
	mu_config_t mu_sm;
#ifdef FILE_INPUT
	int Num_Users, Nr, Nc;
	int bandwidth, Ng;
	int Pkttype;
	int ii, tempNc;
	unsigned int *readPtr, *tempPtr, memOffset;
	unsigned char *writePtr;
	mimo_ctrl_field_t mimo_ctrl_field[8];
#endif
	if (muGID) {
		mu_sm.Pkttype = pktTypeIn;
		mu_sm.Num_Users = numUsers;
		mu_sm.muGID = muGID;

		// copy structure
		size = sizeof(mu_config_t);
		memcpy(bufferPtr, &mu_sm, size);
	} else {		// use file
#ifdef FILE_INPUT
		Num_Users = DEFAULT_NUM_USER;
		Nc = DEFAULT_N_C;
		Nr = DEFAULT_N_R;
		Ng = DEFAULT_NG;
		bandwidth = DEFAULT_BW;
		Pkttype = DEFAULT_PKTTYPE;

		mu_sm.Nr = Nr;
		mu_sm.Nc = 0;
		mu_sm.Ng = Ng;
		mu_sm.Val_BW = bandwidth;
		mu_sm.Pkttype = Pkttype;
		mu_sm.Num_Users = Num_Users;

		memOffset = (sizeof(mu_config_t) + 3) & 0xfffffffc;	// 4 byte aligned
		for (ii = 0; ii < Num_Users; ii++) {
			tempNc = Nc % 10;
			mu_sm.NcArray[ii] = tempNc;
			Nc /= 10;
			mu_sm.Nc += mu_sm.NcArray[ii];
			mu_sm.User_Feedback_Array[ii].addrPtr =
				inputPtr + memOffset;
			size = 3 + tempNc +
				sizeof(unsigned int) *
				compressedInputSizes[tempNc - 1];
			mu_sm.User_Feedback_Array[ii].size = size;
			memOffset += (size + 3) & 0xfffffffc;	// 4 byte aligned

			mimo_ctrl_field[ii].NrIdx = mu_sm.Nr - 1;
			mimo_ctrl_field[ii].ChanWidth = mu_sm.Val_BW;
			mimo_ctrl_field[ii].Ng = mu_sm.Ng;
			mimo_ctrl_field[ii].CodeBook =
				(DEFAULT_B_ANG == 6) ? 1 : 0;
			mimo_ctrl_field[ii].RemSeg = 0;
			mimo_ctrl_field[ii].FstSeg = 1;
			mimo_ctrl_field[ii].token = DEFAULT_DIALOG_TOKEN;
			mimo_ctrl_field[ii].FbType = 1;
			mimo_ctrl_field[ii].NcIdx = tempNc - 1;
		}
		mu_sm.SBF_out.addrPtr = inputPtr + memOffset;
		mu_sm.SBF_out.size = sizeof(goldenQarray);

		// copy structure
		size = sizeof(mu_config_t);
		memcpy(bufferPtr, &mu_sm, size);
		printk("createDspData: No Users: %d, bw: %d, Nr:%d, base ptr: %p\n", Num_Users, bandwidth, Nr, bufferPtr);
		tempPtr = (unsigned int *)bufferPtr;
		printk("createDspData: size: %d, data: %x|%x|%x\n", size,
		       tempPtr[0], tempPtr[1], tempPtr[2]);

		for (ii = 0; ii < Num_Users; ii++) {
			writePtr =
				bufferPtr +
				(mu_sm.User_Feedback_Array[ii].addrPtr -
				 inputPtr);
			tempNc = mimo_ctrl_field[ii].NcIdx;

			tempPtr = (unsigned int *)writePtr;
#ifdef WIRESHARK
			size = 0;
			printk("createDspData: User: %d, Nc:%d, size: %d, start addr: %llx\n", ii, tempNc + 1, size, (long long unsigned)writePtr);
#else
			size = 3 + mu_sm.NcArray[ii];
			memcpy(writePtr, &mimo_ctrl_field, size);
			printk("createDspData: User: %d, Nc:%d, size: %d, start addr: %llx\n", ii, tempNc + 1, size, (long long unsigned)writePtr);
			writePtr += size;
#endif

			size = sizeof(unsigned int) *
				compressedInputSizes[tempNc];
			readPtr = data_ptr_array[ii];
			memcpy(writePtr, readPtr, size);
			printk("createDspData: size: %d, data: %x|%x|%x\n",
			       size, tempPtr[0], tempPtr[1], tempPtr[2]);
		}
		writePtr = bufferPtr + (mu_sm.SBF_out.addrPtr - inputPtr);
		size = sizeof(goldenQarray);
		memcpy(writePtr, &(goldenQarray[0]), size);
		tempPtr = (unsigned int *)writePtr;
		printk("createDspData: base ptr: %llx, size: %d, data: %x|%x|%x\n", (long long unsigned)writePtr, size, tempPtr[0], tempPtr[1], tempPtr[2]);
#else
		return 0;
#endif
	}
	return sizeof(mu_config_t);
}
