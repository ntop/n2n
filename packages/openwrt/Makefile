# Copyright (C) 2021 - ntop.org and contributors
# Copyright (C) 2022 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=n2n
PKG_VERSION:=$(shell ../../scripts/version.sh)
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(CURDIR)/../..

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINER:=Emanuele Faranda <faranda@ntop.org>

PKG_FIXUP:=autoreconf
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/n2n/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=N2N Peer-to-peer VPN
  URL:=http://www.ntop.org/n2n
  SUBMENU:=VPN
  DEPENDS+=+libcap +libpcap +libzstd
endef

define Package/n2n-edge
  $(call Package/n2n/Default)
  TITLE+= client (edge node)
  DEPENDS+=+kmod-tun
endef

define Package/n2n-edge/description
  The client node for the N2N infrastructure
endef

define Package/n2n-edge/conffiles
/etc/n2n/edge.conf
endef

define Package/n2n-supernode
  $(call Package/n2n/Default)
  TITLE+= server (supernode)
endef

define Package/n2n-supernode/description
  The supernode for the N2N infrastructure
endef

define Package/n2n-supernode/conffiles
/etc/n2n/supernode.conf
endef

define Package/n2n-tests
  $(call Package/n2n/Default)
  TITLE+= tests
endef

define Package/n2n-tests/description
  The tests for the N2N infrastructure
endef

define Package/n2n-utils
  $(call Package/n2n/Default)
  TITLE+= utilities
endef

define Package/n2n-utils/description
  The extend utilities for the N2N infrastructure
endef

CONFIGURE_ARGS+= \
	--enable-cap \
	--enable-pcap \
	--enable-zstd

MAKE_VARS+= CONFIG_TARGET=generic

define Package/n2n-edge/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/edge $(1)/usr/bin/edge
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/edge $(1)/etc/init.d/edge
	$(INSTALL_DIR) $(1)/etc/n2n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packages/etc/n2n/edge.conf.sample $(1)/etc/n2n/edge.conf
endef

define Package/n2n-supernode/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/supernode $(1)/usr/bin/supernode
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/supernode $(1)/etc/init.d/supernode
	$(INSTALL_DIR) $(1)/etc/n2n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packages/etc/n2n/supernode.conf.sample $(1)/etc/n2n/supernode.conf
endef

define Package/n2n-tests/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/tests/tests_units.list $(1)/usr/bin/n2n-tests_units.list
	( for i in $$$$(grep -v '#' $(PKG_BUILD_DIR)/tests/tests_units.list); do \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/tools/$$$$i $(1)/usr/bin/n2n-$$$$i ; \
	done )
endef

define Package/n2n-utils/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/n2n-benchmark $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/n2n-decode $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/n2n-keygen $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/n2n-portfwd $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/n2n-route $(1)/usr/bin/
endef

$(eval $(call BuildPackage,n2n-edge))
$(eval $(call BuildPackage,n2n-supernode))
$(eval $(call BuildPackage,n2n-tests))
$(eval $(call BuildPackage,n2n-utils))
