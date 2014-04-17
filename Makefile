#
# Copyright (C) 2010-2012 Owen Kirby <osk@exegin.com>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dnsrt
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/dnsrt
  SECTION:=net
  CATEGORY:=Network
  TITLE:=DNS routing daemon
  MAINTAINER:=Owen Kirby <oskirby@gmail.com>
endef

define Package/dnsrt/description
	A routing daemon that listens for DNS messages and updates the routing
	table with redirects based on domain name matches.
endef

# Specify the config files for the sep2 package.
define Package/sep2/conffiles
/etc/config/dnsrt
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/dnsrt/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsrt $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/dnsrt.init $(1)/etc/init.d/dnsrt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/dnsrt.config $(1)/etc/config/dnsrt
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	$(CP) ./luasrc/* $(1)/usr/lib/lua/luci
endef

$(eval $(call BuildPackage,dnsrt))

