# Findings

## EFI signing and Secure Boot

The unlock EFI is launched directly by firmware, so Secure Boot checks its
signer against UEFI `db`; MOK alone does not authorize this boot entry. A
signature table confirms that an image is signed, but only firmware can confirm
that the signer is trusted. Signing the EFI does not sign the patched Linux
kernel modules, which need their own trusted signature.

Evidence: [Cyridd/cmpunlocker Secure Boot guide](https://github.com/Cyridd/cmpunlocker/blob/main/windows/README.md#secure-boot) and this project's direct `efibootmgr` EFI entry.
