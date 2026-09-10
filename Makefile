# CMP 50HX unlock — one-shot local release (mirrors .github/workflows/release.yml)
#
#   make release       build the Linux .run + the Windows zip locally
#   make efi           build just the Linux EFI binary
#   make win           build just the Windows Go tools + zip
#   make clean         remove all build outputs

CARGO_OS_LINUX  := linux/amd64
INSTALLER       := cmp50hx-unlock-linux.run
PAYLOAD_TGZ     := cmp50hx-unlock-linux.tar.gz
WIN_ZIP         := cmp50hx-unlock-windows.zip
STAGE_DIR       := .release-stage
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
SHA             := $(shell sha256sum $(PAYLOAD_TGZ) 2>/dev/null | awk '{print $$1}')

.PHONY: all release efi win clean

all: release

# ------------------------------------------------------------------
# Linux side
# ------------------------------------------------------------------
efi:
	cd efi-unlock && ./build.sh

$(PAYLOAD_TGZ): efi
	rm -rf $(STAGE_DIR); mkdir -p $(STAGE_DIR)
	cp install.sh                                          $(STAGE_DIR)/
	cp -r efi-unlock/blobs                                  $(STAGE_DIR)/blobs
	cp efi-unlock/README.md efi-unlock/unlock50x_v1.c        $(STAGE_DIR)/
	cp efi-unlock/build.sh                                  $(STAGE_DIR)/
	cp efi-unlock/50HXUNLK.EFI                              $(STAGE_DIR)/
	sha256sum efi-unlock/50HXUNLK.EFI                       > $(STAGE_DIR)/50HXUNLK.EFI.sha256
	tar -C $(STAGE_DIR) -czf $(PAYLOAD_TGZ) .
	sha256sum $(PAYLOAD_TGZ) > $(PAYLOAD_TGZ).sha256
	@echo "wrote $(PAYLOAD_TGZ) ($(shell wc -c < $(PAYLOAD_TGZ)) bytes)"

$(INSTALLER): $(PAYLOAD_TGZ)
	CMP_VERSION=$(VERSION) \
	CMP_RELEASE_URL="file://$$(pwd)/$(PAYLOAD_TGZ)" \
	CMP_RELEASE_SHA=$(SHA) \
	  bash tools/build-linux-installer.sh \
	    --tar $(PAYLOAD_TGZ) \
	    --out $(INSTALLER)
	@echo "wrote $(INSTALLER) ($(shell wc -c < $(INSTALLER)) bytes)"

# ------------------------------------------------------------------
# Windows side (requires Go 1.23+ on PATH; PowerShell for the zip)
# ------------------------------------------------------------------
win:
	@command -v go >/dev/null 2>&1 || (echo "need go 1.23+ on PATH" && exit 2)
	@command -v pwsh >/dev/null 2>&1 || (echo "need pwsh on PATH" && exit 2)
	./tools/build-windows.ps1 -Version $(VERSION) -Source . -Out $(WIN_ZIP)

# ------------------------------------------------------------------
# Aggregate
# ------------------------------------------------------------------
release: $(INSTALLER) win
	@echo
	@echo "===== Linux installer ====="
	ls -la $(INSTALLER) $(PAYLOAD_TGZ) $(PAYLOAD_TGZ).sha256
	@echo
	@echo "===== Windows bundle ====="
	ls -la $(WIN_ZIP) 2>/dev/null || echo "(Windows build skipped — install Go + pwsh)"
	@echo
	@echo "User install (Linux):   sudo ./$(INSTALLER)"
	@echo "User install (Win):    unzip and run 50HXInstaller.exe as admin"

clean:
	rm -f efi-unlock/50HXUNLK.EFI efi-unlock/*.o efi-unlock/*.so
	rm -rf $(STAGE_DIR)
	rm -f $(INSTALLER) $(PAYLOAD_TGZ) $(PAYLOAD_TGZ).sha256 $(WIN_ZIP)
	rm -rf artifacts/
