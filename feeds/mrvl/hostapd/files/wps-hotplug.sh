#!/bin/bash

if [ "$ACTION" = "pressed" -a "$BUTTON" = "wps" ]; then
#	cd /var/run/hostapd
#	for socket in *; do 
#		[ -S "$socket" ] || continue
#		hostapd_cli -i "$socket" wps_pbc
#	done

    mapvalue=" "
    easymesh_configured_2G=`cat /easymesh/wlan_ma.config | grep "ieee80211.complete_config_2G" | awk -F = '{printf $2}'`
	easymesh_configured_5G=`cat /easymesh/wlan_ma.config | grep "ieee80211.complete_config_5G" | awk -F = '{printf $2}'`
     
    wdev0sta0_up=`ifconfig | grep -o wdev0sta0`
    wdev1sta0_up=`ifconfig | grep -o wdev1sta0`

	if [ -e /var/run/agent.pid  -a  "$easymesh_configured_2G" == "0" -a  "$easymesh_configured_5G" == "0"\
         -a "$wdev0sta0_up" == "" -a "$wdev1sta0_up" == "" ] ; then
	    cd /easymesh && ./backhaul_STA_start.sh &      
	else
	    cd /var/run/hostapd
	    for socket in wdev*; do
	        [ -S "$socket" ] || continue
	        read mapvalue <<< $(printf "0x%x\n" $(iwpriv "$socket" getcmd multiap | awk '/multiap/ {print $2;}' | sed 's/getcmd:multiap://g'))
            if [ "$mapvalue" == "0x20" -o "$mapvalue" == "0x60" -o "$mapvalue" == "96" -o "$mapvalue" == "32" -o "$mapvalue" == "0" ] ; then
                hostapd_cli -i "$socket" wps_pbc > /dev/console 
	        fi
	    done
	fi
fi

case "$ACTION" in
pressed)
	return 5
;;
timeout)
	. /etc/diag.sh
	set_state failsafe
;;
released)
	if [ "$SEEN" -gt 5 ]
	then
		echo "FACTORY RESET" > /dev/console
		jffs2reset -y && reboot &
	fi
;;
esac

return 0
