#!/bin/sh

AP_PRIVATE_KEY_FILE="/usr/opensync/certs/client_dec.key"
AP_CERTIFICATE_FILE="/usr/opensync/certs/client.pem"
AP_DEVICE_ID_FILE="/usr/opensync/certs/client_deviceid.txt"
DIGICERT_API_URI="clientauth.one.digicert.com"

if [ "$1" = "-h" ]; then
  echo "Usage: $0 [redirector address]" >&2
  exit 1
fi

# Query DigiCert's API if redirector wasn't specified
if [ -z "$1" ]; then
  if [ ! -f "$AP_DEVICE_ID_FILE" ]; then
      echo "Device ID file $AP_DEVICE_ID_FILE does not exist. Make sure to create it or specify the redirector address manually."
      exit 1
  fi

  # TODO: this command should be retried if it fails
  digicert_device_id=`cat ${AP_DEVICE_ID_FILE}`
  device_data=`curl -s \
    --key "${AP_PRIVATE_KEY_FILE}" \
    --cert "${AP_CERTIFICATE_FILE}" \
    "https://${DIGICERT_API_URI}/iot/api/v2/device/${digicert_device_id}"`

  controller_url=`echo ${device_data} | jsonfilter -e '@.fields[@.name="Redirector"].value'`
  # TODO: we should get the port with the redirector record and only default to 6643 if no port was specified
  redirector_addr="ssl:${controller_url}:6643"
else
  redirector_addr=$1
fi

uci set system.tip.redirector="${redirector_addr}"
uci commit system
/etc/init.d/opensync restart
