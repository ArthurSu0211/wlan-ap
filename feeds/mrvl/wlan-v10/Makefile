#
# Copyright (C) 2014-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wlan-v10
PKG_RELEASE=1

PKG_LICENSE:=ISC
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=Jinhua Zhang <zhangjh@marvell.com>
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

SOURCE_CODE_DIR:=$(PKG_BUILD_DIR)/DRV/wlan-v10
SHAL_INCLUDE:=$(PKG_BUILD_DIR)/SHAL/shal1/include
CMIF_INCLUDE:=$(PKG_BUILD_DIR)/CMIF/include

DRIVER_MAKEOPTS = \
	SOC=W906x \
	PLATFORM=A390 \
	HOST=OPENWRT \
	BUILD_CFG80211=1
ifdef CONFIG_WLAN_V10_AOA
	DRIVER_MAKEOPTS += AOA_ONLY=1
endif
ifdef CONFIG_WLAN_V10_WLS
	DRIVER_MAKEOPTS += WLS=1
endif

define KernelPackage/wlan-v10
  SUBMENU:=Wireless Drivers
  TITLE:=Marvell 88W9064/88W9068 wireless driver
  DEPENDS:=+@DRIVER_11N_SUPPORT @PCI_SUPPORT @TARGET_cn9130 +@KERNEL_PERF_EVENTS
  FILES:=$(PKG_BUILD_DIR)/DRV/wlan-v10/ap8x.ko
  #AUTOLOAD:=$(call AutoLoad,51,ap8x)
endef

define KernelPackage/wlan-v10/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r src/* $(PKG_BUILD_DIR)
	rm -f $(SOURCE_CODE_DIR)/Makefile
	$(CP) $(SOURCE_CODE_DIR)/build/linux/Makefile $(SOURCE_CODE_DIR)
	find $(SOURCE_CODE_DIR) -type f -exec chmod +w {} \;
endef

define Build/Compile
		$(MAKE) V=1 $(PKG_JOBS) -C "$(SOURCE_CODE_DIR)" \
			KDIR="$(LINUX_DIR)" \
			ARCH="$(LINUX_KARCH)" \
			CROSS_COMPILE="$(TARGET_CROSS)" \
			PWD="$(SOURCE_CODE_DIR)" \
			SHAL_INC="$(SHAL_INCLUDE)" \
			CMIF_INC="$(CMIF_INCLUDE)" \
			$(DRIVER_MAKEOPTS) \
            all
endef

define KernelPackage/wlan-v10/install
		$(INSTALL_DIR) $(1)/lib/firmware
		$(INSTALL_DIR) $(1)/lib/firmware/marvell
		$(INSTALL_DIR) $(1)/root
		$(INSTALL_DIR) $(1)/etc
		$(INSTALL_DIR) $(1)/etc/init.d
		$(CP) $(PKG_BUILD_DIR)/W9064-AP-24.4.25.0-P1066.00_2020-02-11.bin $(1)/lib/firmware/marvell/W9064.bin
		#$(CP) $(PKG_BUILD_DIR)/W9064.bin $(1)/lib/firmware/marvell/W9064-AP.bin
		#$(CP) $(PKG_BUILD_DIR)/W9068.bin $(1)/lib/firmware/marvell/W9068-AP.bin
		$(CP) ./files/* $(1)/
		$(CP) ./files/etc/* $(1)/etc
		$(INSTALL_BIN) ./files/etc/ap_sta_swap.sh $(1)/etc/
		$(CP) ./files/etc/init.d/* $(1)/etc/init.d
		$(CP) ./files/etc/config/* $(1)/etc/config
endef

$(eval $(call KernelPackage,wlan-v10))
