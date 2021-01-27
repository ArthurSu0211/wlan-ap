#!/bin/sh
. /lib/netifd/netifd-wireless.sh
. /lib/netifd/hostapd.sh

init_wireless_driver "$@"

MP_CONFIG_INT="mesh_retry_timeout mesh_confirm_timeout mesh_holding_timeout mesh_max_peer_links
	       mesh_max_retries mesh_ttl mesh_element_ttl mesh_hwmp_max_preq_retries
	       mesh_path_refresh_time mesh_min_discovery_timeout mesh_hwmp_active_path_timeout
	       mesh_hwmp_preq_min_interval mesh_hwmp_net_diameter_traversal_time mesh_hwmp_rootmode
	       mesh_hwmp_rann_interval mesh_gate_announcements mesh_sync_offset_max_neighor
	       mesh_rssi_threshold mesh_hwmp_active_path_to_root_timeout mesh_hwmp_root_interval
	       mesh_hwmp_confirmation_interval mesh_awake_window mesh_plink_timeout"
MP_CONFIG_BOOL="mesh_auto_open_plinks mesh_fwding"
MP_CONFIG_STRING="mesh_power_mode"

drv_marvell_init_device_config() {
	logger "init_device_config: $1 $2"
	logger $(json_dump)
	config_add_boolean optlevel rifs preamble gprotect htprotect dhenable dmode hdfsmode hcsamode intolerant40 beamforming antennamode
	config_add_int regioncode agingtime ratectl ratemode ratestbc ratedcm ratebandwidth rategi rateltf ratelegacy raten \
                rateac rateax ratenss ratepreamble rategf rateldpc ratebf rateantenna htpc hcsacount hnoptout hcactout mumimo \
		       opmode monchannel monhtmode
	config_add_string secondchannel
}

drv_marvell_init_iface_config() {
	logger "init_iface_config: $1 $2"
	logger $(json_dump)
	config_add_string bandsteerintf
	config_add_boolean intrabss wdsenable wpsenable bandsteer macclone
	config_add_int bkcwminap bkcwmaxap bkaifsnap bktxopblap bktxopglap bkcwminsta bkcwmaxsta bkaifsnsta bktxopblsta bktxopglsta \
		bkacm becwminap becwmaxap beaifsnap betxopblap betxopglap becwminsta becwmaxsta beaifsnsta betxopblsta betxopglsta beacm \
		vicwminap vicwmaxap viaifsnap vitxopblap vitxopglap vicwminsta vicwmaxsta viaifsnsta vitxopblsta vitxopglsta viacm \
		vocwminap vocwmaxap voaifsnap votxopblap votxopglap vocwminsta vocwmaxsta voaifsnsta votxopblsta votxopglsta voacm \
		disableassoc wdsport wdsmacaddr wdsmode amsdu ampdutx fltmode maclist1 maclist2 maclist3 maclist4 maclist5 index ieee80211w \
		multiapattr backhaulsta
}

marvell_hostapd_setup_bss() {
	local ifname="$1"
	local type="$2"

	hostapd_cfg=
	append hostapd_cfg "bridge=br-lan" "$N"
	append hostapd_cfg "driver=nl80211" "$N"
	append hostapd_cfg "$type=$ifname" "$N"
	append hostapd_cfg "ctrl_interface=/var/run/hostapd" "$N"
	append hostapd_cfg "ctrl_interface_group=0" "$N"
	append hostapd_cfg "ap_isolate=0" "$N"
	append hostapd_cfg "ignore_broadcast_ssid=0" "$N"
	append hostapd_cfg "uapsd_advertisement_enabled=1" "$N"

	cat >> /var/run/hostapd-$ifname.conf <<EOF
$hostapd_cfg
EOF
}

marvell_setup_dev() {
	logger "marvell_setup_dev: $1"
	local wmm=$2
	json_select config
	json_get_vars channel txantenna rxantenna rts hwmode htmode beacon_int greenfield tx_stbc short_gi_20 optlevel rifs preamble \
		regioncode agingtime gprotect ratectl ratemode ratestbc ratedcm ratebandwidth rategi rateltf ratelegacy raten rateac \
                rateax ratenss ratepreamble rategf rateldpc ratebf rateantenna dhenable dmode hdfsmode htpc hcsamode \
		hcsacount hnoptout hcactout intolerant40 beamforming htprotect mumimo opmode secondchannel antennamode monchannel monhtmode \
		extsubch pwrfraction MCS
	json_select ..
	
	#TR069 changes to add freqband to UCI
	local freqband=`uci get wireless.radio${1#radio}.freqband`
	if [ -z "$freqband" ]; then
		local phy="phy${1#radio}"
		local freq=`iw phy $phy info | grep  "MHz.*dBm" | head -1 | awk '{print $2}'`
		[ "${freq#24}" = "$freq" ] && freqband="5GHz" || freqband="2.4GHz"
		uci set wireless.radio${1#radio}.freqband="$freqband"
		uci commit
	fi
	#end TR069 changes to add freqband to UCI

	#TR069 changes to add extension channel to UCI
	#set value if doesn't exist yet
	local defextsubch=`uci get wireless.radio${1#radio}.extsubch`
	if [ -z "$defextsubch" ]; then
		local phy=${1#radio}
		local ext=`iwpriv wdev"$phy" getextsubch | cut -d : -f2 | awk '{ print $1}'`
		if [ "$ext" = "0" ]; then
		    defextsubch="Auto"
		elif	 [ "$ext" = "1" ]; then
		    defextsubch="BelowControlChannel"
		elif [ "$ext" = "2" ]; then
		    defextsubch="AboveControlChannel"
		fi
		uci set wireless.radio${1#radio}.extsubch="$defextsubch"
		uci commit
	fi
	#end TR069 changes to add extension channel to UCI

	#TR069 change to set extension channel if user sets UCI
	case "$extsubch" in
		"Auto")
		    iwpriv wdev${1#radio} extsubch 0
		;;
		"BelowControlChannel")
		    iwpriv wdev${1#radio} extsubch 1
		;;
		"AboveControlChannel")
		    iwpriv wdev${1#radio} extsubch 2
		;;
	esac
	#end TR069 changes to set extension channel if user sets UCI
	
	case "$htmode" in
		*20*)
		    iwpriv wdev${1#radio} htbw 2
		;;
		*40*)
		    iwpriv wdev${1#radio} htbw 3
		;;
		*80*)
		    iwpriv wdev${1#radio} htbw 4
		;;
		*160*)
		    iwpriv wdev${1#radio} htbw 5
		;;
		*)
		    iwpriv wdev${1#radio} htbw 0
		;;
	esac

	#TR069 change to add possible channels to UCI
	local poschannel=`uci get wireless.radio${1#radio}.poschannel`
	if [ -z "$poschannel" ]; then
		local phy=${1#radio}
		local chan
		if [ "$phy" == "0" ]; then
			chan=`iwpriv wdev0 getcmd getchnls | grep 036`
		else
			chan=`iwpriv wdev1 getcmd getchnls | grep 01`
		fi
		uci set wireless.radio${1#radio}.poschannel="$chan"
		uci commit
	fi
	#end TR069 changes to add possible channels to UCI
	
	if [ -n "$regioncode" ]; then
		iwpriv wdev${1#radio} regioncode $regioncode
	fi

	case "$channel" in
		"auto")
			iwpriv wdev${1#radio} autochannel 1
		;;
		*)
			iwpriv wdev${1#radio} autochannel 0
			iwconfig wdev${1#radio} channel $channel
		;;
	esac

	#TR069 change to add 80211h supported to UCI
	local gethmode=`uci get wireless.radio${1#radio}.hmodesupp`
	if [ -z "$hmodesupp" ]; then
		local gethmode
		if [ ${1#radio} = "1" ]; then
		     gethmode="false"
		else
		     gethmode=`iwpriv wdev"${1#radio}" get11hcsamode | cut -d : -f2 | awk '{ print $1}'`
		fi
		uci set wireless.radio${1#radio}.hmodesupp="$gethmode"
		uci commit
	fi
	#end TR069 changes to add 80211h supported to UCI
	
	#TR069 change to add transmit power supported to UCI
	local getpsupp=`uci get wireless.radio${1#radio}.powersupp`
	if [ -z "$getpsupp" ]; then
		uci set wireless.radio${1#radio}.powersupp="0, 25, 50, 75, 100"
		uci commit
	fi
	#end TR069 change to add transmit power supported to UCI

	#TR069 change to add transmit power fraction to UCI
	local getpwrfrac=`uci get wireless.radio${1#radio}.pwrfraction`
	if [ -z "$getpwrfrac" ]; then
		local pfrac=`iwpriv wdev"${1#radio}" getpwrfraction | cut -d : -f2 | awk '{ print $1}'`
		if [ "$pfrac" = "0" ]; then
			pfrac=100
		elif [ "$pfrac" = "1" ]; then
			pfrac=75
		elif [ "$pfrac" = "2" ]; then
			pfrac=50
		elif [ "$pfrac" = "3" ]; then
			pfrac=25
		elif [ "$pfrac" = "4" ]; then
			pfrac=0
		elif [ "$pfrac" = "5" ]; then
			pfrac=0
		fi
		uci set wireless.radio${1#radio}.pwrfraction="$pfrac"
		uci commit
	fi
	#end TR069 change to add transmit power fraction to UCI

	#TR069 change to set transmit power fraction if user sets UCI
	if [ -n "$pwrfraction" ]; then
		if [ "$pwrfraction" = "0" ]; then
			`iwpriv wdev"${1#radio}" pwrfraction 4`
		elif [ "$pwrfraction" = "25" ]; then
			`iwpriv wdev"${1#radio}" pwrfraction 3`
		elif [ "$pwrfraction" = "50" ]; then
			`iwpriv wdev"${1#radio}" pwrfraction 2`
		elif [ "$pwrfraction" = "75" ]; then
			`iwpriv wdev"${1#radio}" pwrfraction 1`
		elif [ "$pwrfraction" = "100" ]; then
			`iwpriv wdev"${1#radio}" pwrfraction 0`
		fi
	fi
	#end TR069 change to set transmit power fraction if user sets UCI

	#TR069 change to add MCS to UCI
	local getMCS=`uci get wireless.radio${1#radio}.MCS`
	if [ -z "$getMCS" ]; then
		uci set wireless.radio${1#radio}.MCS="-1"
		uci commit
	fi
	#end TR069 change to add MCS to UCI

	#TR069 change to set MCS if user sets UCI
	if [ -n "$MCS" ]; then
		#hex bits - 8 total
		local firsthexbit
		if [ "$hwmode" == "11n" ]; then
			firsthexbit="1"
		elif [ "$hwmode" == "11ac" ]; then
			firsthexbit="2"
		elif [ "$hwmode" == "11ax" ]; then
			firsthexbit="3"
		else
			firsthexbit="0"
		fi
		
		local bw="00"
		case "$htmode" in
		*20*)
		    bw="00"
		;;
		*40*)
		    bw="01"
		;;
		*80*)
		    bw="10"
		;;
		*160*)
		    bw="11"
	esac
		
		local gint
		if [ "$short_gi_20" == "2" ]; then
			gint="00"
		else
			gint="01"
		fi
		local secondhexbit
		local binarysgibw="$gint$bw"
		if [ "$binarysgibw" == "0000" ]; then
			secondhexbit=0
		elif [ "$binarysgibw" == "0001" ]; then
			secondhexbit=1
		elif [ "$binarysgibw" == "0010" ]; then
			secondhexbit=2
		elif [ "$binarysgibw" == "0011" ]; then
			secondhexbit=3
		elif [ "$binarysgbiw" == "0100" ]; then
			secondhexbit=4
		elif [ "$binarysgibw" == "0101" ]; then
			secondhexbit=5
		elif [ "$binarysgibw" == "0110" ]; then
			secondhexbit=6
		elif [ "$binarysgbiw" == "0111" ]; then
			secondhexbit=7
		fi
		local thirdhexbix="$MCS"
		local fourthhexbit="0"
		if [ "$MCS" == "-1" ]; then
			thirdhexbit="0"
		elif [ "$MCS" == "0" ]; then
			thirdhexbit="0"
		elif [ "$MCS" == "1" ]; then
			thirdhexbit=1
		elif [ "$MCS" == "2" ]; then
			thirdhexbit=2
		elif [ "$MCS" == "3" ]; then
			thirdhexbit=3
		elif [ "$MCS" == "4" ]; then
			thirdhexbit=4
		elif [ "$MCS" == "5" ]; then
			thirdhexbit=5
		elif [ "$MCS" == "6" ]; then
			thirdhexbit=6
		elif [ "$MCS" == "7" ]; then
			thirdhexbit=7
		elif [ "$MCS" == "8" ]; then
			thirdhexbit=8
		elif [ "$MCS" == "9" ]; then
			thirdhexbit=9
		elif [ "$MCS" == "10" ]; then
			thirdhexbit="a"
		elif [ "$MCS" == "11" ]; then
			thirdhexbit="b"
		elif [ "$MCS" == "12" ]; then
			thirdhexbit="c"
		elif [ "$MCS" == "13" ]; then
			thirdhexbit="d"
		elif [ "$MCS" == "14" ]; then
			thirdhexbit="e"
		elif [ "$MCS" == "15" ]; then
			thirdhexbit="f"
		elif [ "$MCS" -ge "16" ]; then
			fourthhexbit=$((MCS - 16))
			thirdhexbit="f"
		fi
		local lasthexbits="ff01"
		local setval="0x"$lasthexbits""$fourthhexbit""$thirdhexbit""$secondhexbit""$firsthexbit""
		`iwpriv wdev${1#radio} setcmd "txratectrl type 3 val "$setval""`

	fi
	#end TR069 change to set MCS if user sets UCI
	
	if [ -n "$secondchannel" ]; then
		if [ "$secondchannel" != "auto" ];then
			iwpriv wdev${1#radio} setcmd "radiomode 1 $secondchannel"
		fi
	else
		iwpriv wdev${1#radio} setcmd "radiomode 0"
	fi

	if [ $dhenable == "1" ]; then
		if [ -n "$dmode" ]; then
			iwpriv wdev${1#radio} 11dmode $dmode
		fi

		if [ -n "$hdfsmode" ]; then
			iwpriv wdev${1#radio} 11hspecmgt $hdfsmode
		fi

		if [ -n "$htpc" ]; then
			iwpriv wdev${1#radio} 11hpwrconstr $htpc
		fi

		if [ -n "$hcsamode" ]; then
			iwpriv wdev${1#radio} 11hcsamode $hcsamode
		fi

		if [ -n "$hcsacount" ]; then
			iwpriv wdev${1#radio} 11hcsacount $hcsacount
		fi

		if [ -n "$hnoptout" ]; then
			iwpriv wdev${1#radio} 11hNOPTimeOut $hnoptout
		fi

		if [ -n "$hcactout" ]; then
			iwpriv wdev${1#radio} 11hCACTimeOut $hcactout
		fi
	fi

	case "$txantenna" in
		0)
			iwpriv wdev${1#radio} txantenna 0x0
		;;
		1)
			iwpriv wdev${1#radio} txantenna 0x1
		;;
		2)
			iwpriv wdev${1#radio} txantenna 0x3
		;;
		3)
			iwpriv wdev${1#radio} txantenna 0x7
		;;
		4)
			iwpriv wdev${1#radio} txantenna 0xF
		;;
		5)
			iwpriv wdev${1#radio} txantenna 0x1F
		;;
		6)
			iwpriv wdev${1#radio} txantenna 0x3F
		;;
		7)
			iwpriv wdev${1#radio} txantenna 0x7F
		;;
		8)
			iwpriv wdev${1#radio} txantenna 0xFF
		;;
	esac

	case "$rxantenna" in
		0)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x0"
		;;
		1)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x1"
		;;
		2)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x3"
		;;
		3)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x7"
		;;
		4)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0xF"
		;;
		5)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x1F"
		;;
		6)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x3F"
		;;
		7)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0x7F"
		;;
		8)
			iwpriv wdev${1#radio} setcmd "rxantbitmap 0xFF"
		;;
	esac

	if [ -n "$rts" ]; then
		iwconfig wdev${1#radio} rts $rts
	fi

	if [ -n "$optlevel" ]; then
		iwpriv wdev${1#radio} optlevel $optlevel
	fi

	if [ -n "$greenfield" ]; then
		iwpriv wdev${1#radio} htgf $greenfield
	fi

	if [ -n "$tx_stbc" ]; then
		iwpriv wdev${1#radio} htstbc $tx_stbc
	fi


	if [ -n "$short_gi_20" ]; then
		iwpriv wdev${1#radio} guardint $short_gi_20
	fi


	if [ -n "$rifs" ]; then
		iwpriv wdev${1#radio} setcmd "rifs $rifs"
	fi

	if [ -n "$preamble" ]; then
		iwpriv wdev${1#radio} preamble $preamble
	fi

	if [ -n "$beacon_int" ]; then
		iwpriv wdev${1#radio} bcninterval $beacon_int
	fi

	if [ -n "$agingtime" ]; then
		iwpriv wdev${1#radio} agingtime $agingtime
	fi

	if [ -n "$gprotect" ]; then
		iwpriv wdev${1#radio} gprotect $gprotect
	fi

	if [ -n "$htprotect" ]; then
		iwpriv wdev${1#radio} htprotect $htprotect
	fi

	if [ -n "$ratectl" ]; then
		case "$ratectl" in
			0)
				iwpriv wdev${1#radio} setcmd "txratectrl type 1 val"
			;;
			1)
				case "$ratemode" in
					0)
						val=`expr $ratemode + 16 \* $ratebandwidth + 64 \* $rategi + 256 \* $ratelegacy + 32768 \* $ratepreamble + 16777216 \* $rateantenna`
						val_hex=`printf "0x%08x" $val`
						iwpriv wdev${1#radio} setcmd "txratectrl type 3 val $val_hex"
						logger "Rate mode: $ratemode Set rate value: $val_hex"
					;;
					1)
						val=`expr $ratemode + 4 \* $ratestbc + 16 \* $ratebandwidth + 64 \* $rategi + 256 \* $raten + 32768 \* $rategf + 4194304 \* $rateldpc + 8388608 \* $ratebf + 16777216 \* $rateantenna`
						val_hex=`printf "0x%08x" $val`
						iwpriv wdev${1#radio} setcmd "txratectrl type 3 val $val_hex"
						logger "Rate mode: $ratemode Set rate value: $val_hex"
					;;
					2)
						val=`expr $ratemode + 4 \* $ratestbc + 16 \* $ratebandwidth + 64 \* $rategi + 256 \* $rateac + 4096 \* $ratenss + 4194304 \* $rateldpc + 8388608 \* $ratebf + 16777216 \* $rateantenna`
						val_hex=`printf "0x%08x" $val`
						iwpriv wdev${1#radio} setcmd "txratectrl type 3 val $val_hex"
						logger "Rate mode: $ratemode Set rate value: $val_hex"
					;;
					3)
						val=`expr $ratemode + 4 \* $ratestbc + 8 \* $ratedcm + 16 \* $ratebandwidth + 64 \* $rateltf + 256 \* $rateax + 4096 \* $ratenss + 4194304 \* $rateldpc + 8388608 \* $ratebf + 16777216 \* $rateantenna`
						val_hex=`printf "0x%08x" $val`
						iwpriv wdev${1#radio} setcmd "txratectrl type 3 val $val_hex"
						logger "Rate mode: $ratemode Set rate value: $val_hex"
					;;
					*)
						logger "Rate mode $ratemode is not supported"
					;;
				esac
			;;
			*)
				logger "ratectl $ratectl is not supported"
			;;
		esac
	fi

	if [ -n "$intolerant40" ]; then
		iwpriv wdev${1#radio} setcmd "intolerant40 $intolerant40"
	fi

	if [ -n "$beamforming" ]; then
		if [ "$beamforming" == "1" ]; then
			iwpriv wdev${1#radio} setcmd "set_bftype 6"
		else
			iwpriv wdev${1#radio} setcmd "set_bftype 5"
		fi
	fi

	if [ -n "$wmm" ]; then
		iwpriv wdev${1#radio} wmm $wmm
	fi


	if [ -n "$opmode" ]; then
		case $opmode in
			60|55|54|40|39|28|24|23|12|8|7|6|4|3|2|1)
				iwpriv wdev${1#radio} opmode $opmode
			;;
			*)
				logger "opmode:${opmode} not supported!"
			;;
		esac
	fi
	
	if [ $antennamode == "1" ]; then
		if [ $monchannel -gt 11 ]; then
		    FreqBand2=4
	    else
	    	FreqBand2=1
	    fi
	    
		case "$monhtmode" in
			*20*)
				ChnlWidth=2
			;;
			*40*)
				ChnlWidth=4
			;;
			*80*)
				ChnlWidth=5
			;;
		esac
		
	iwpriv wdev${1#radio} setcmd  "radiomode 2 $FreqBand2 $monchannel $ChnlWidth"
	fi
	
	iwconfig wdev${1#radio} commit
}

marvell_setup_supplicant() {
	wpa_supplicant_prepare_interface "$ifname" marvell || return 1
	wpa_supplicant_add_network "$ifname"
}

marvell_setup_vif() {
	logger "marvell_setup_vif: $1"
	local name="$1"
	json_select config
	json_get_vars phy ifname mode macaddr ssid encryption key key1 key2 key3 key4 hidden dtim_period auth_server auth_port \
		auth_secret acct_server acct_port acct_secret nasid isolate wmm macclone bkcwminap bkcwmaxap bkaifsnap \
		bktxopblap bktxopglap bkcwminsta bkcwmaxsta bkaifsnsta bktxopblsta bktxopglsta bkacm becwminap becwmaxap beaifsnap \
		betxopblap betxopglap becwminsta becwmaxsta beaifsnsta betxopblsta betxopglsta beacm vicwminap vicwmaxap viaifsnap \
		vitxopblap vitxopglap vicwminsta vicwmaxsta viaifsnsta vitxopblsta vitxopglsta viacm vocwminap vocwmaxap voaifsnap \
		votxopblap votxopglap vocwminsta vocwmaxsta voaifsnsta votxopblsta votxopglsta voacm wdsenable disableassoc wdsport \
		wdsmacaddr wdsmode amsdu ampdutx wpsenable bssid fltmode maclist1 maclist2 maclist3 maclist4 maclist5 index \
		bandsteer bandsteerintf ieee80211w multiapattr backhaulsta extiface maxassoc wpa_group_rekey

	case "$mode" in
		"ap")
			[ -n "$ifname" ] || ifname="wdev${phy#radio}ap${index}"

			hostapd_conf_file="/var/run/hostapd-$ifname.conf"

			# Hostapd will handle recreating the interface
			type=interface

			marvell_hostapd_setup_bss "$ifname" "$type" || return
		;;
		"sta")
			[ -n "$ifname" ] || ifname="wdev${phy#radio}sta0"
		;;
	esac

	ip link set dev "$ifname" down

	hostapd_cfg=
	append hostapd_cfg "ssid=$ssid" "$N"
	#TR069 changes to add isolation to UCI
	append hostapd_cfg "max_num_sta=$maxassoc" "$N"
	#end TR069 change to add guard interval to UCI
	#append hostapd_cfg "beacon_int=$beacon_int" "$N"
	append hostapd_cfg "dtim_period=$dtim_period" "$N"
	append hostapd_cfg "bssid=$bssid" "$N"
	if [ "$channel" == "auto" ]; then
		append hostapd_cfg "channel=0" "$N"
	else
		append hostapd_cfg "channel=$channel" "$N"
	fi

	maclist1=`echo $maclist1 | sed 's/://g'`
	maclist2=`echo $maclist2 | sed 's/://g'`
	maclist3=`echo $maclist3 | sed 's/://g'`
	maclist4=`echo $maclist4 | sed 's/://g'`
	maclist5=`echo $maclist5 | sed 's/://g'`

	wdsmacaddr=`echo $wdsmacaddr | sed 's/://g'`
	bssid=`echo $bssid | sed 's/://g'`
	
	#TR069 change to add group rekey to UCI
	local getrekey=`uci get wireless.@wifi-iface[$uci_index].wpa_group_rekey`
	if [ -z "$getrekey" ]; then
		local value=`iwpriv "$ifname" getgrouprekey | cut -d : -f2 | awk '{ print $1}'`
		uci set wireless.@wifi-iface[$uci_index].wpa_group_rekey="$value"
		uci commit
	fi
    #end TR069 changes to set isolation if user sets UCI
	
	if [ -n "$opmode" ]; then
		case $opmode in
			60)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211ac=1" "$N"
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			40)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211ac=1" "$N"
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			28)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211ac=1" "$N"
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			39)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			54)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			55)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			24)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211ac=1" "$N"
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			23)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			12)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211n=1" "$N"
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			8)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=a" "$N"
				append hostapd_cfg "track_sta_max_num=100" "$N"
				append hostapd_cfg "track_sta_max_age=180" "$N"
			;;
			7)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				append hostapd_cfg "ieee80211n=1" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			6)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				append hostapd_cfg "ieee80211n=1" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			4)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "ieee80211n=1" "$N"
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			3)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			2)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			1)
				iwpriv $ifname opmode $opmode
				append hostapd_cfg "hw_mode=g" "$N"
				if [ "$bandsteer" == "1" ]; then
					append hostapd_cfg "no_probe_resp_if_seen_on=$bandsteerintf" "$N"
					append hostapd_cfg "no_auth_if_seen_on=$bandsteerintf" "$N"
				fi
			;;
			*)
				logger "opmode:${opmode} not supported!"
			;;
		esac
	fi

	if [ -n "$amsdu" ]; then
		iwpriv "$ifname" amsdu $amsdu
	fi

	if [ -n "$ampdutx" ]; then
		iwpriv "$ifname" ampdutx $ampdutx
	fi


	if [ -n "$isolate" ]; then
		if [ "$isolate" == "1" ]; then
			iwpriv "$ifname" intrabss 0
		else
			iwpriv "$ifname" intrabss 1
		fi
    fi

	if [ "$mode" == "sta" ]; then
		iwconfig $ifname essid $ssid
		if [ "$phy" == "radio0" ]; then
			iwpriv $ifname stamode 8
		elif [ "$phy" == "radio1" ]; then
			case $opmode in
				60|40|28|24|23|12|8)
					iwpriv $ifname stamode 8
				;;
				55|54|39|6|4|3|2|1)
					iwpriv $ifname stamode 7
				;;
				*)
					logger "opmode:${opmode} not supported!"
				;;
			esac
		fi

		if [ -n "$macclone" ]; then
			iwpriv $ifname macclone $macclone
		fi

		if [ -n "$bkcwminsta" -a -n "$bkcwmaxsta" -a -n "$bkaifsnsta" -a -n "$bktxopblsta" -a -n "$bktxopglsta" -a -n "$bkacm" ]; then
			iwpriv "$ifname" wmmedcasta "1 $bkcwminsta $bkcwmaxsta $bkaifsnsta $bktxopblsta $bktxopglsta $bkacm"
		fi

		if [ -n "$becwminsta" -a -n "$becwmaxsta" -a -n "$beaifsnsta" -a -n "$betxopblsta" -a -n "$betxopglsta" -a -n "$beacm" ]; then
			iwpriv "$ifname" wmmedcasta "0 $becwminsta $becwmaxsta $beaifsnsta $betxopblsta $betxopglsta $beacm"
		fi

		if [ -n "$vicwminsta" -a -n "$vicwmaxsta" -a -n "$viaifsnsta" -a -n "$vitxopblsta" -a -n "$vitxopglsta" -a -n "$viacm" ]; then
			iwpriv "$ifname" wmmedcasta "2 $vicwminsta $vicwmaxsta $viaifsnsta $vitxopblsta $vitxopglsta $viacm"
		fi

		if [ -n "$vocwminsta" -a -n "$vocwmaxsta" -a -n "$voaifsnsta" -a -n "$votxopblsta" -a -n "$votxopglsta" -a -n "$voacm" ]; then
			iwpriv "$ifname" wmmedcasta "3 $vocwminsta $vocwmaxsta $voaifsnsta $votxopblsta $votxopglsta $voacm"
		fi
    fi
	case "$encryption" in
		"psk+tkip")
			echo "WPA TKIP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 0
				#iw mdev $ifname set wpawpa2mode 1
				#iw mdev $ifname set passphrase wpa $key
				#iw mdev $ifname set grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=1" "$N"
				append hostapd_cfg "wpa_pairwise=TKIP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				#TR069 changes to set grouprekey if user sets UCI
				if [ -n "$wpa_group_rekey" ]; then
					append hostapd_cfg "wpa_group_rekey=$wpa_group_rekey" "$N"
				else
				    append hostapd_cfg "wpa_group_rekey=1800" "$N"
				fi
				#end TR069 changes to set grouprekey if user sets UCI
			fi
		;;
		"psk2+ccmp")
			echo "WPA2 CCMP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 0
				#iw mdev $ifname set wpawpa2mode 2
				#iw mdev $ifname set passphrase wpa2 $key
				#iw mdev $ifname set grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=2" "$N"
				append hostapd_cfg "wpa_pairwise=CCMP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				#TR069 changes to set grouprekey if user sets UCI
				if [ -n "$wpa_group_rekey" ]; then
					append hostapd_cfg "wpa_group_rekey=$wpa_group_rekey" "$N"
				else
					append hostapd_cfg "wpa_group_rekey=1800" "$N"
				fi
				#end TR069 changes to set grouprekey if user sets UCI
			fi
		;;
		"psk-mixed+tkip+ccmp")
			echo "WPA-TKIP/WPA2-CCMP"
			if [ "$mode" == "sta" ]; then
				iwpriv $ifname wpawpa2mode 0
				#iw mdev $ifname set wpawpa2mode 3
				#iw mdev $ifname set passphrase "wpa $key"
				#iw mdev $ifname set passphrase "wpa2 $key"
				#iw mdev $ifname set grouprekey 1800
			elif [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=3" "$N"
				append hostapd_cfg "wpa_pairwise=TKIP" "$N"
				append hostapd_cfg "rsn_pairwise=CCMP" "$N"
				append hostapd_cfg "wpa_key_mgmt=WPA-PSK" "$N"
				append hostapd_cfg "wpa_passphrase=$key" "$N"
				#TR069 changes to set grouprekey if user sets UCI
				if [ -n "$wpa_group_rekey" ]; then
					append hostapd_cfg "wpa_group_rekey=$wpa_group_rekey" "$N"
				else
					append hostapd_cfg "wpa_group_rekey=1800" "$N"
				fi
				#end TR069 changes to set grouprekey if user sets UCI
			fi
		;;
		"sae+ccmp")
			echo "SAE CCMP"
			if [ "$mode" == "ap" ]; then
				iwpriv $ifname wpawpa2mode 0
				append hostapd_cfg "auth_algs=1" "$N"
				append hostapd_cfg "wpa=2" "$N"
				append hostapd_cfg "wpa_pairwise=CCMP" "$N"
				append hostapd_cfg "wpa_key_mgmt=SAE" "$N"
				append hostapd_cfg "sae_password=$key" "$N"
				#TR069 changes to set grouprekey if user sets UCI
				if [ -n "$wpa_group_rekey" ]; then
					append hostapd_cfg "wpa_group_rekey=$wpa_group_rekey" "$N"
				else
					append hostapd_cfg "wpa_group_rekey=1800" "$N"
				fi
				#end TR069 changes to set grouprekey if user sets UCI
			fi
		;;
		"wpa+tkip")
			echo "WPA-EAP TKIP"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=1" "$N"
			append hostapd_cfg "ieee8021x=1" "$N"
			append hostapd_cfg "wpa_pairwise=TKIP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			
			#TR069 changes to add secondary radius server
            # List of fallback RADIUS server IP addresses
			json_select "auth_servers"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				ip_addr=$(echo "$Var")
				append hostapd_cfg "auth_server_addr=$ip_addr" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server ports
			json_select "auth_ports"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				port=$(echo "$Var")
				if ! echo "$port" | egrep -q '^[0-9]+$' ; then
					port=1812
				fi
				append hostapd_cfg "auth_server_port=$port" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server secrets
			json_select "auth_secrets"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				secret=$(echo "$Var")
				append hostapd_cfg "auth_server_shared_secret=$secret" "$N"
			done
			json_select ".."

			#append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			#append hostapd_cfg "auth_server_port=$auth_port" "$N"
			#append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			#end TR069 changes to add secondary radius server
			
			if [ -n "$acct_server" ] ; then
				append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			fi
			if [ -n "$acct_port" ] ; then
				append hostapd_cfg "acct_server_port=$acct_port" "$N"
			fi
			if [ -n "$acct_secret" ] ; then
				append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			fi
			if [ -n "$nasid" ] ; then
				append hostapd_cfg "nas_identifier=$nasid" "$N"
			fi
		;;
		"wpa2+ccmp")
			echo "WPA2-EAP CCMP"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=2" "$N"
			append hostapd_cfg "ieee8021x=1" "$N"
			append hostapd_cfg "wpa_pairwise=CCMP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			
			#TR069 changes to add secondary radius server
            # List of fallback RADIUS server IP addresses
			json_select "auth_servers"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				ip_addr=$(echo "$Var")
				append hostapd_cfg "auth_server_addr=$ip_addr" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server ports
			json_select "auth_ports"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				port=$(echo "$Var")
				if ! echo "$port" | egrep -q '^[0-9]+$' ; then
					port=1812
				fi
				append hostapd_cfg "auth_server_port=$port" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server secrets
			json_select "auth_secrets"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				secret=$(echo "$Var")
				append hostapd_cfg "auth_server_shared_secret=$secret" "$N"
			done
			json_select ".."

			#append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			#append hostapd_cfg "auth_server_port=$auth_port" "$N"
			#append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			#end TR069 changes to add secondary radius server
			
			if [ -n "$acct_server" ] ; then
				append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			fi
			if [ -n "$acct_port" ] ; then
				append hostapd_cfg "acct_server_port=$acct_port" "$N"
			fi
			if [ -n "$acct_secret" ] ; then
				append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			fi
			if [ -n "$nasid" ] ; then
				append hostapd_cfg "nas_identifier=$nasid" "$N"
			fi
		;;
		"wpa-mixed+tkip+ccmp")
			echo "WPA-EAP TKIP/WPA2-EAP CCMP Mixed"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=3" "$N"
			append hostapd_cfg "ieee8021x=1" "$N"
			append hostapd_cfg "wpa_pairwise=TKIP" "$N"
			append hostapd_cfg "rsn_pairwise=CCMP" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			
			#TR069 changes to add secondary radius server
            # List of fallback RADIUS server IP addresses
			json_select "auth_servers"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				ip_addr=$(echo "$Var")
				append hostapd_cfg "auth_server_addr=$ip_addr" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server ports
			json_select "auth_ports"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				port=$(echo "$Var")
				if ! echo "$port" | egrep -q '^[0-9]+$' ; then
					port=1812
				fi
				append hostapd_cfg "auth_server_port=$port" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server secrets
			json_select "auth_secrets"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				secret=$(echo "$Var")
				append hostapd_cfg "auth_server_shared_secret=$secret" "$N"
			done
			json_select ".."

			#append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			#append hostapd_cfg "auth_server_port=$auth_port" "$N"
			#append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			#end TR069 changes to add secondary radius server
			
			if [ -n "$acct_server" ] ; then
				append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			fi
			if [ -n "$acct_port" ] ; then
				append hostapd_cfg "acct_server_port=$acct_port" "$N"
			fi
			if [ -n "$acct_secret" ] ; then
				append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			fi
			if [ -n "$nasid" ] ; then
				append hostapd_cfg "nas_identifier=$nasid" "$N"
			fi
		;;
		"suiteb")
			echo "SUITEB192"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=2" "$N"
			append hostapd_cfg "ieee8021x=1" "$N"
			append hostapd_cfg "rsn_pairwise=GCMP-256" "$N"
			append hostapd_cfg "wpa_key_mgmt=WPA-EAP-SUITE-B-192" "$N"
			append hostapd_cfg "group_mgmt_cipher=BIP-GMAC-256" "$N"
			append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			append hostapd_cfg "auth_server_port=$auth_port" "$N"
			append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			
			#TR069 changes to add secondary radius server
            # List of fallback RADIUS server IP addresses
			json_select "auth_servers"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				ip_addr=$(echo "$Var")
				append hostapd_cfg "auth_server_addr=$ip_addr" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server ports
			json_select "auth_ports"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				port=$(echo "$Var")
				if ! echo "$port" | egrep -q '^[0-9]+$' ; then
					port=1812
				fi
				append hostapd_cfg "auth_server_port=$port" "$N"
			done
			json_select ".."

                        # List of fallback RADIUS server secrets
			json_select "auth_secrets"
			local Index="1"
			while json_get_type Var $Index && [ "$Var" = string ]; do
				json_get_var Var "$((Index++))"
				secret=$(echo "$Var")
				append hostapd_cfg "auth_server_shared_secret=$secret" "$N"
			done
			json_select ".."
			#append hostapd_cfg "auth_server_addr=$auth_server" "$N"
			#append hostapd_cfg "auth_server_port=$auth_port" "$N"
			#append hostapd_cfg "auth_server_shared_secret=$auth_secret" "$N"
			#end TR069 changes to add secondary radius server
			
			if [ -n "$acct_server" ] ; then
				append hostapd_cfg "acct_server_addr=$acct_server" "$N"
			fi
			if [ -n "$acct_port" ] ; then
				append hostapd_cfg "acct_server_port=$acct_port" "$N"
			fi
			if [ -n "$acct_secret" ] ; then
				append hostapd_cfg "acct_server_shared_secret=$acct_secret" "$N"
			fi
			if [ -n "$nasid" ] ; then
				append hostapd_cfg "nas_identifier=$nasid" "$N"
			fi
		;;
		"wep-shared")
			echo "WEP shared"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=2" "$N"
			append hostapd_cfg "wpa=0" "$N"
			append hostapd_cfg "wep_key0=$key1" "$N"
			append hostapd_cfg "wep_key1=$key2" "$N"
			append hostapd_cfg "wep_key2=$key3" "$N"
			append hostapd_cfg "wep_key3=$key4" "$N"
			if [ -n "$key1" ]; then
				echo "WEP key1 $key1"
				iwconfig $ifname key $key1 [1]
				#iw mdev $ifname set wepkey string 1 $key1
			fi
			if [ -n "$key2" ]; then
				echo "WEP key2 $key2"
				iwconfig $ifname key $key2 [2]
				#iw mdev $ifname set wepkey string 2 $key2
			fi
			if [ -n "$key3" ]; then
				echo "WEP key3 $key3"
				iwconfig $ifname key $key3 [3]
				#iw mdev $ifname set wepkey string 3 $key3
			fi
			if [ -n "$key4" ]; then
				echo "WEP key4 $key4"
				iwconfig $ifname key $key4 [4]
				#iw mdev $ifname set wepkey string 4 $key4
			fi
			iwconfig $ifname key $key restricted
			#iw mdev $ifname set wepkey $key restricted

		;;
		"wep-open")
			echo "WEP open"
			iwpriv $ifname wpawpa2mode 0
			append hostapd_cfg "auth_algs=1" "$N"
			append hostapd_cfg "wpa=0" "$N"
			append hostapd_cfg "wep_key0=$key1" "$N"
			append hostapd_cfg "wep_key1=$key2" "$N"
			append hostapd_cfg "wep_key2=$key3" "$N"
			append hostapd_cfg "wep_key3=$key4" "$N"
			if [ -n "$key1" ]; then
				echo "WEP key1 $key1"
				iwconfig $ifname key $key1 [1]
				#iw mdev $ifname set wepkey string 1 $key1
			fi
			if [ -n "$key2" ]; then
				echo "WEP key2 $key2"
				iwconfig $ifname key $key2 [2]
				#iw mdev $ifname set wepkey string 2 $key2
			fi
			if [ -n "$key3" ]; then
				echo "WEP key3 $key3"
				iwconfig $ifname key $key3 [3]
				#iw mdev $ifname set wepkey string 3 $key3
			fi
			if [ -n "$key4" ]; then
				echo "WEP key4 $key4"
				iwconfig $ifname key $key4 [4]
				#iw mdev $ifname set wepkey string 4 $key4
			fi
			iwconfig $ifname key $key open
			#iw mdev $ifname set wepkey $key open
		;;
		"none")
			echo "Open"
			append hostapd_cfg "wpa=0" "$N"
			iwpriv $ifname wpawpa2mode 0
			iwconfig $ifname key off
			#iw mdev $ifname set wepkey off
		;;
		*)
			echo "Enc:$encryption NOT supported"
		;;
	esac

	if [ "$wpsenable" == "1" ]; then
		append hostapd_cfg "ieee8021x=0" "$N"
		append hostapd_cfg "eapol_key_index_workaround=0" "$N"
		append hostapd_cfg "eap_server=1" "$N"
		append hostapd_cfg "wps_state=2" "$N"
		append hostapd_cfg "ap_setup_locked=0" "$N"
		append hostapd_cfg "device_type=6-0050F204-1" "$N"
		append hostapd_cfg "device_name=Marvell AP" "$N"
		append hostapd_cfg "manufacturer=Marvell, LLC" "$N"
		append hostapd_cfg "model_name=88W8964" "$N"
		append hostapd_cfg "model_number=88W8964" "$N"
		append hostapd_cfg "serial_number=12345678908888" "$N"
		append hostapd_cfg "wps_pin_requests=/var/run/hostapd_wps_pin_requests" "$N"
		append hostapd_cfg "config_methods=label display push_button virtual_display virtual_push_button physical_push_button" "$N"
		append hostapd_cfg "uuid=075ECB0B-6129-7C29-FA5B-CC6F40100899" "$N"
		append hostapd_cfg "upnp_iface=br-lan" "$N"
		append hostapd_cfg "friendly_name=Marvell" "$N"
		append hostapd_cfg "model_description=Marvell Wireless AC Gigabit Router" "$N"
		wpsappin=$(uci get wps.@wps[0].router_pin)
		append hostapd_cfg "ap_pin=$wpsappin" "$N"
	fi

	if [ "$multiapattr" == "1" ]; then
		append hostapd_cfg "multi_ap=frontBSS" "$N"
		if [ "$ifname" == "wdev0ap0" ]; then
			append hostapd_cfg "ext_iface=wdev0ap1" "$N"
		elif [ "$ifname" == "wdev1ap0" ]; then
			append hostapd_cfg "ext_iface=wdev1ap1" "$N"
		fi
	elif [ "$multiapattr" == "2" ]; then
		append hostapd_cfg "multi_ap=backBSS" "$N"
	elif [ "$multiapattr" == "3" ]; then
		append hostapd_cfg "multi_ap=frontBSS backBSS" "$N"
	fi

	if [ -n "$extiface" -a "$extiface" != "null" ]; then
		append hostapd_cfg "ext_iface=$extiface" "$N"
	fi

	append hostapd_cfg "okc=0" "$N"
	append hostapd_cfg "disable_pmksa_caching=1" "$N"

	if [ "$mode" == "ap" ]; then
		if [ -n "$fltmode" ]; then
			iwpriv "$ifname" filter $fltmode
			if [ "$fltmode" == "0" ]; then
				iwpriv "$ifname" filtermac "deleteall"
			fi
		fi

		if [ -n "$maclist1" ]; then
			iwpriv "$ifname" filtermac "add $maclist1"
		fi

		if [ -n "$maclist2" ]; then
			iwpriv "$ifname" filtermac "add $maclist2"
		fi

		if [ -n "$maclist3" ]; then
			iwpriv "$ifname" filtermac "add $maclist3"
		fi

		if [ -n "$maclist4" ]; then
			iwpriv "$ifname" filtermac "add $maclist4"
		fi

		if [ -n "$maclist5" ]; then
			iwpriv "$ifname" filtermac "add $maclist5"
		fi

		if [ -n "$dtim_period" ]; then
			iwpriv "$ifname" dtim $dtim_period
		fi

		if [ -n "$bssid" ]; then
			iwpriv "$ifname" bssid $bssid
		fi

		if [ -n "$hidden" ]; then
			iwpriv "$ifname" hidessid $hidden
		fi

		if [ -n "$bkcwminap" -a -n "$bkcwmaxap" -a -n "$bkaifsnap" -a -n "$bktxopblap" -a -n "$bktxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "1 $bkcwminap $bkcwmaxap $bkaifsnap $bktxopblap $bktxopglap"
		fi

		if [ -n "$becwminap" -a -n "$becwmaxap" -a -n "$beaifsnap" -a -n "$betxopblap" -a -n "$betxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "0 $becwminap $becwmaxap $beaifsnap $betxopblap $betxopglap"
		fi

		if [ -n "$vicwminap" -a -n "$vicwmaxap" -a -n "$viaifsnap" -a -n "$vitxopblap" -a -n "$vitxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "2 $vicwminap $vicwmaxap $viaifsnap $vitxopblap $vitxopglap"
		fi

		if [ -n "$vocwminap" -a -n "$vocwmaxap" -a -n "$voaifsnap" -a -n "$votxopblap" -a -n "$votxopglap" ]; then
			iwpriv "$ifname" wmmedcaap "3 $vocwminap $vocwmaxap $voaifsnap $votxopblap $votxopglap"
		fi

		if [ -n "$ieee80211w" ]; then
			if [ "$encryption" == "sae+ccmp" ] && [ "$ieee80211w" == "0" ]; then
				append hostapd_cfg "ieee80211w=1" "$N"
			else
				append hostapd_cfg "ieee80211w=$ieee80211w" "$N"
			fi
		fi

		if [ "$phy" == "radio0" ]; then
			if [ -n "$mumimo" ]; then
				if [ "$mumimo" == "2" -o "$mumimo" == "0" ]; then
					iwpriv "$ifname" setcmd "set_mumimomgmt 0"
				elif [ "$mumimo" == "1" ]; then
					iwpriv "$ifname" setcmd "set_mumimomgmt 1"
				fi
			fi
		fi

	fi
	if [ -n "$wdsenable" ]; then
		if [ $wdsenable -eq 0 ] ; then
			brctl delif br-lan ${ifname}wds${wdsport}
		fi

		iwpriv "$ifname" wdsmode $wdsenable
	fi

	if [ -n "$wdsenable" -a -n "$disableassoc" -a -n "$wdsport" -a -n "$wdsmacaddr" -a -n "$wdsmode" ]; then
		iwpriv "$ifname" disableassoc $disableassoc
		iwpriv "$ifname" setwds "$wdsport $wdsmacaddr $wdsmode"
		ifconfig ${ifname}wds${wdsport} up
		brctl addif br-lan ${ifname}wds${wdsport}
	fi

	wireless_add_vif $name $ifname

	if [ "$mode" == "ap" ]; then
		ip link set dev "$ifname" up
		cat >> /var/run/hostapd-$ifname.conf <<EOF
$hostapd_cfg
EOF
	elif [ "$mode" == "sta" ]; then
		if [ -n "$backhaulsta" ]; then
			if [ "$backhaulsta" == "1" ]; then
				#iwpriv $ifname amsdu 0
				iwpriv $ifname setcmd "multiap 128"
				iwpriv $ifname setcmd "eap_rate_fixed 1"
			fi
		fi
		if [ "$encryption" != "wep-shared" ] && [ "$encryption" != "wep-open" ]; then
			marvell_setup_supplicant
		fi
		ip link set dev "$ifname" up
	fi

	json_select ..
}

marvell_interface_cleanup() {
	local phy="wdev${1#radio}"

	for wdev in $(list_phy_interfaces "$phy"); do
		ip link set dev "$wdev" down 2>/dev/null
	done
}

marvell_wpad_cleanup() {
	rm -rf /var/run/hostapd-wdev${1#radio}*.conf
	rm -rf /var/run/wpa_supplicant-wdev${1#radio}*.conf
}

drv_marvell_cleanup() {
	lk="/var/lock/marvell.lock"
	lock -u $lk
	logger "drv_marvell_cleanup: $1"
	logger $(json_dump)
}

drv_marvell_setup() {
	lk="/var/lock/marvell.lock"
	lock -w $lk
	lock $lk	
	logger "drv_marvell_setup: $1"
	local vif_ifaces vif_iface
	logger $(json_dump)
	json_get_keys vif_ifaces interfaces
	json_select interfaces
	for vif_iface in $vif_ifaces; do
		json_select "$vif_iface"
		json_select config
		json_add_string phy "$1"
		json_get_var wmm wmm
		json_select ..
		json_select ..
	done
	json_select ..

	marvell_interface_cleanup "$1"

	marvell_wpad_cleanup "$1"

	marvell_setup_dev "$1" "$wmm"

	mfg_mode=`fw_printenv mfg_mode`
	mfg_mode=${mfg_mode#*=}
	if [ "$mfg_mode" == "2" ]; then
		for_each_interface "sta" marvell_setup_vif
	else
		for_each_interface "ap sta" marvell_setup_vif
	fi

	wireless_set_up
	lock -u $lk
}

list_phy_interfaces() {
	local phy="$1"
	ls "/sys/class/net/" 2>/dev/null|egrep "^${phy}\w+"
}

drv_marvell_teardown() {
	lk="/var/lock/marvell.lock"
	lock -u $lk
	logger "drv_marvell_teardown: $1"
	echo $(json_dump)

	echo "cleanup phy: $1"
	hostapd_common_cleanup
	marvell_interface_cleanup "$1"
}

add_driver marvell
