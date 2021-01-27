append DRIVERS "marvell"

AAscan_marvell() {
	local device="$1"
	local vif vifs wds
	local adhoc sta apmode mon disabled
	local adhoc_if sta_if ap_if mon_if
}

AAdisable_marvell() {
	local device="$1"
	echo "disable interface $1"
	for wdev in $(ls /sys/class/net/ 2>/dev/null | grep ^$1); do
		ifconfig $wdev down
	done
}

AAenable_marvell() {
	local device="$1"
	local channel country maxassoc wds vifs distance slottime rxantenna txantenna
	local frameburst macfilter maclist macaddr txpower frag rts hwmode htmode
	config_get channel "$device" channel
	config_get country "$device" country
	config_get maxassoc "$device" maxassoc
	config_get wds "$device" wds
	config_get vifs "$device" vifs
	config_get distance "$device" distance
	config_get slottime "$device" slottime
	config_get rxantenna "$device" rxantenna
	config_get txantenna "$device" txantenna
	config_get_bool frameburst "$device" frameburst
	config_get macfilter "$device" macfilter
	config_get maclist "$device" maclist
	config_get txpower "$device" txpower
	config_get frag "$device" frag
	config_get rts "$device" rts
	config_get hwmode "$device" hwmode
	config_get htmode "$device" htmode
	local apcount=0
	local anyup=0
	local netdev=wdev${device#radio}

	echo "channel is $channel, device is $device, netdev is $netdev"
	ifconfig $netdev down
	for vif in $vifs; do
		config_get vifssid "$vif" ssid
		config_get vifwdev "$vif" device
		config_get vifenc "$vif" encryption
		config_get vifdisable "$vif" disabled
		local vifdev=wdev${vifwdev#radio}ap$apcount
		echo "disabled: $vifdisable, ssid: $vifssid, vapdev: $vifdev dev: $vifwdev, enc: $vifenc"
		ifconfig $vifdev down
		if [ "$vifdisable" = "1" ]; then
			echo "skip disabled vif"
			continue
		fi
		if [ -n "$vifssid" ]; then
			iwconfig $vifdev essid $vifssid
		fi
		if [ "$vifdisable" != "none" ]; then
			config_get vifkey "$vif" key
			echo "key: $vifkey"
		fi
		case "$vifenc" in
			"psk2"|"psk2+ccmp"|"psk2+tkip+ccmp")
				echo "WPA2 AES-CCMP"
				iwpriv $vifdev wpawpa2mode 2
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa2 aes-ccmp"
			;;
			"psk2+tkip")
				echo "WPA2 TKIP"
				iwpriv $vifdev wpawpa2mode 2
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa2 tkip"
			;;
			"psk+psk2")
				echo "WPA/WPA2"
				iwpriv $vifdev wpawpa2mode 3
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa tkip"
				iwpriv $vifdev ciphersuite "wpa2 aes-ccmp"
			;;
			"psk"|"psk+tkip"|"psk+tkip+ccmp")
				echo "WPA TKIP"
				iwpriv $vifdev wpawpa2mode 1
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa tkip"
			;;
			"psk"|"psk+ccmp")
				echo "WPA AES-CCMP"
				iwpriv $vifdev wpawpa2mode 1
				iwpriv $vifdev passphrase "wpa $vifkey"
				iwpriv $vifdev passphrase "wpa2 $vifkey"
				iwpriv $vifdev ciphersuite "wpa aes-ccmp"
			;;
			"none")
				echo "Open"
				iwpriv $vifdev wpawpa2mode 0
			;;
			*)
				echo "Enc:$vifenc NOT supported"
			;;
		esac
		apcount=$(($apcount+1))
		ifconfig $vifdev up
		anyup=1
	done
	if [ "$anyup" = "1" ]; then
		echo "Up $netdev"
		ifconfig $netdev up
	fi
}


detect_marvell() {
	local i=-1
	while grep -qs "^ *wdev$((++i)):" /proc/net/dev; do
		local channel type
		mode_band="g"
		channel="6"
		bandwith="HT40"
		essid="AP9064-OpenWiFi-"
		opmode="55"

		config_get type radio${i} type
		[ "$type" = marvell ] && continue
		#channel=`iwconfig wdev${i} |grep Channel|cut -d ":" -f2|cut -d " " -f1`
		hwaddr=`cat /sys/class/net/wdev${i}ap0/address`
		if [ "$i" = "0" ]; then
			channel="36"
			mode_band="a"
			bandwith="VHT80"
			essid="AP9064-OpenWiFi-5G-"
			opmode="60"
		fi
		cat <<EOF
config wifi-device  radio${i}
	option type     marvell
	option channel  ${channel:-11}
	option txantenna 0
	option rxantenna 0
	option rts 65535
	option optlevel 1
	option beacon_int 100
	option greenfield 0
	option tx_stbc 0
	option short_gi_20 0
	option rifs 0
	option preamble 0
	option regioncode 0x10
	option agingtime 7200
	option gprotect 0
	option htprotect 0
	option hwmode	11${mode_band}
	option htmode	${bandwith}
	option ratectl 0
	option dhenable 0
	option dmode 0
	option hdfsmode 0
	option htpc 3
	option hcsamode 1
	option hcsacount 20
	option hnoptout 1800
	option hcactout 60
	option intolerant40 1
	option beamforming 1
	option mumimo 2
	option opmode ${opmode}
	option antennamode 0
EOF
	for x in $(seq 1 17)
	do
	cat <<EOF
config wifi-iface
	option device   radio${i}
	option disabled 1
EOF
	done
	cat <<EOF
config wifi-iface
	option device   radio${i}
	option network	lan
	option mode     ap
	option ssid     ${essid}1
	option bssid	${hwaddr}
	option disabled 0
	option encryption none
	option hidden 0
	option dtim_period 1
	option isolate 0
	option wmm 1
	option fltmode 0
	option bkcwminap 15
	option bkcwmaxap 1023
	option bkaifsnap 7
	option maxassoc 320
	option bktxopblap 0
	option bktxopglap 0
	option becwminap 15
	option becwmaxap 63
	option beaifsnap 3
	option betxopblap 0
	option betxopglap 0
	option vicwminap 7
	option vicwmaxap 15
	option viaifsnap 1
	option vitxopblap 188
	option vitxopglap 94
	option vocwminap 3
	option vocwmaxap 7
	option voaifsnap 1
	option votxopblap 102
	option votxopglap 47
	option wdsenable 0
	option disableassoc 1
	option wdsport 0
	option wdsmode g
	option amsdu 3
	option ampdutx 1
	option wpsenable 0
	option index 0
	option bandsteer 0
	option ieee80211w 0
	option extiface null
EOF
	for cnt in $(seq 2 16)
	do
	idx=$(($cnt-1))
	hwaddr=`cat /sys/class/net/wdev${i}ap${idx}/address`
	cat <<EOF
config wifi-iface
	option device   radio${i}
	option mode     ap
	option ssid     ${essid}${cnt}
	option bssid	${hwaddr}
	option disabled 1
	option encryption none
	option hidden 0
	option dtim_period 1
	option intrabss 1
	option wmm 1
	option fltmode 0
	option bkcwminap 15
	option bkcwmaxap 1023
	option maxassoc 320
	option bkaifsnap 7
	option bktxopblap 0
	option bktxopglap 0
	option becwminap 15
	option becwmaxap 63
	option beaifsnap 3
	option betxopblap 0
	option betxopglap 0
	option vicwminap 7
	option vicwmaxap 15
	option viaifsnap 1
	option vitxopblap 188
	option vitxopglap 94
	option vocwminap 3
	option vocwmaxap 7
	option voaifsnap 1
	option votxopblap 102
	option votxopglap 47
	option wdsenable 0
	option disableassoc 1
	option wdsport 0
	option wdsmode g
	option amsdu 3
	option ampdutx 1
	option wpsenable 0
	option index ${idx}
	option bandsteer 0
	option ieee80211w 0
	option extiface null
EOF
	done
cat <<EOF
config wifi-iface
	option device radio${i}
	option ssid ${essid}STA
	option bssid FF:FF:FF:FF:FF:FF
	option encryption none
	option mode sta
	option disabled 1
	option intrabss 1
	option wmm 1
	option macclone 0
	option bkcwminsta 15
	option bkcwmaxsta 1023
	option bkaifsnsta 7
	option bktxopblsta 0
	option bktxopglsta 0
	option bkacm 0
	option becwminsta 15
	option becwmaxsta 1023
	option maxassoc 320
	option beaifsnsta 3
	option betxopblsta 0
	option betxopglsta 0
	option beacm 0
	option vicwminsta 7
	option vicwmaxsta 15
	option viaifsnsta 2
	option vitxopblsta 188
	option vitxopglsta 94
	option viacm 0
	option vocwminsta 3
	option vocwmaxsta 7
	option voaifsnsta 2
	option votxopblsta 102
	option votxopglsta 47
	option voacm 0
	option amsdu 3
	option ampdutx 1
	option backhaulsta 0
EOF
	done
}
