SHELL := /bin/bash
VERSION := $(shell cat VERSION)
ROOT_DIR := /opt
PROJECT := keenetic-policy-ui
OUT_DIR := out
BUILD_DIR := build
IPK := $(OUT_DIR)/$(PROJECT)_$(VERSION)_all_entware.ipk

.DEFAULT_GOAL := all
.PHONY: all clean

all: $(IPK)

clean:
	rm -rf $(OUT_DIR)

$(IPK): _prep _control _data _package
	@echo ""
	@echo "Package built: $(IPK)"
	@ls -lh $(IPK)

_prep:
	rm -rf $(OUT_DIR)/$(BUILD_DIR)
	mkdir -p $(OUT_DIR)/$(BUILD_DIR)/control
	mkdir -p $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/share/www/$(PROJECT)/api
	mkdir -p $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/etc/lighttpd/conf.d
	mkdir -p $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/etc/keenetic-policy-ui

_control:
	@echo "Package: $(PROJECT)" > $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "Version: $(VERSION)" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "Depends: lighttpd, lighttpd-mod-cgi, lighttpd-mod-setenv, lighttpd-mod-rewrite, lighttpd-mod-redirect, php8-cgi, php8-mod-curl" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "License: MIT" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "Section: net" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "URL: https://github.com/JohnDoe150489/keenetic-policy-ui/" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "Architecture: all" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "Description: Web UI for managing per-device VPN policies on Keenetic routers" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	@echo "" >> $(OUT_DIR)/$(BUILD_DIR)/control/control
	cp ipk/conffiles $(OUT_DIR)/$(BUILD_DIR)/control/conffiles
	cp ipk/postinst $(OUT_DIR)/$(BUILD_DIR)/control/postinst
	chmod +x $(OUT_DIR)/$(BUILD_DIR)/control/postinst
	cp ipk/prerm $(OUT_DIR)/$(BUILD_DIR)/control/prerm
	chmod +x $(OUT_DIR)/$(BUILD_DIR)/control/prerm
	cd $(OUT_DIR)/$(BUILD_DIR)/control && tar czvf ../control.tar.gz . && cd ../../..

_data:
	cp public/index.html $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/share/www/$(PROJECT)/
	cp public/app.js $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/share/www/$(PROJECT)/
	cp public/style.css $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/share/www/$(PROJECT)/
	cp api/index.php $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/share/www/$(PROJECT)/api/
	cp etc/lighttpd/conf.d/80-keenetic-policy-ui.conf $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/etc/lighttpd/conf.d/
	cp etc/keenetic-policy-ui/keenetic-policy-ui.conf $(OUT_DIR)/$(BUILD_DIR)/data$(ROOT_DIR)/etc/keenetic-policy-ui/
	cd $(OUT_DIR)/$(BUILD_DIR)/data && tar czvf ../data.tar.gz . && cd ../../..

_package:
	echo 2.0 > $(OUT_DIR)/$(BUILD_DIR)/debian-binary
	cd $(OUT_DIR)/$(BUILD_DIR) && tar czvf $(PROJECT)_$(VERSION)_all_entware.ipk control.tar.gz data.tar.gz debian-binary
	mv $(OUT_DIR)/$(BUILD_DIR)/$(PROJECT)_$(VERSION)_all_entware.ipk $(IPK)
	rm -rf $(OUT_DIR)/$(BUILD_DIR)
