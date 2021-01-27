#!/bin/sh

role=`uci get dev_role.@devicerole[0].role`

mfg_mode=`fw_printenv mfg_mode`
mfg_mode=${mfg_mode#*=} 

if [ "$role" == "ap" ] && [ "$mfg_mode" != "0" ] ; then
	fw_setenv mfg_mode 0
	reboot
fi

if [ "$role" == "sta" ] && [ "$mfg_mode" != "2" ]  ; then
	fw_setenv mfg_mode 2
	reboot
fi