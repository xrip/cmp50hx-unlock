package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const signedEFIName = "50HXUNLK.signed.EFI"

// loadEFIImage uses -efi when given, else a personal signed EFI beside the
// installer, and finally the reproducible unsigned embedded image.
func loadEFIImage() ([]byte, string, bool, error) {
	path, err := selectedEFIPath()
	if err != nil {
		return nil, "", false, err
	}

	var data []byte
	source := "embedded 50HXUNLK.EFI"
	if path != "" {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, path, false, fmt.Errorf("read EFI %q: %w", path, err)
		}
		source = path
	} else {
		data, err = embedded.ReadFile("embed/50HXUNLK.EFI")
		if err != nil {
			return nil, source, false, err
		}
	}

	if len(data) < 0x2000 {
		return nil, source, false, fmt.Errorf("EFI image is too small (%d bytes)", len(data))
	}
	if len(data) < 2 || string(data[:2]) != "MZ" {
		return nil, source, false, fmt.Errorf("EFI image %q is not a PE image", source)
	}
	return data, source, peHasAuthenticodeSignature(data), nil
}

func selectedEFIPath() (string, error) {
	if i := argIndex("-efi"); i >= 0 {
		if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
			return "", fmt.Errorf("-efi requires a signed EFI file path")
		}
		return filepath.Abs(os.Args[i+1])
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	for _, candidate := range []string{
		filepath.Join(filepath.Dir(exe), signedEFIName),
		filepath.Join(".", signedEFIName),
	} {
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return filepath.Abs(candidate)
		}
	}
	return "", nil
}

// peHasAuthenticodeSignature checks for a well-formed PKCS#7 certificate table.
// Firmware still decides whether its signer is trusted in the UEFI db.
func peHasAuthenticodeSignature(data []byte) bool {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return false
	}
	pe := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if pe < 0 || pe+24 > len(data) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return false
	}
	coff := pe + 4
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16 : coff+18]))
	optional := coff + 20
	if optionalSize < 2 || optional+optionalSize > len(data) {
		return false
	}

	var countOffset, directoryOffset int
	switch binary.LittleEndian.Uint16(data[optional : optional+2]) {
	case 0x10b:
		countOffset, directoryOffset = 92, 96 // PE32
	case 0x20b:
		countOffset, directoryOffset = 108, 112 // PE32+
	default:
		return false
	}
	if countOffset+4 > optionalSize ||
		binary.LittleEndian.Uint32(data[optional+countOffset:optional+countOffset+4]) <= 4 ||
		directoryOffset+5*8 > optionalSize {
		return false
	}

	security := optional + directoryOffset + 4*8
	certOffset := uint64(binary.LittleEndian.Uint32(data[security : security+4]))
	certSize := uint64(binary.LittleEndian.Uint32(data[security+4 : security+8]))
	if certOffset == 0 || certSize < 8 || certOffset+certSize > uint64(len(data)) {
		return false
	}
	recordSize := uint64(binary.LittleEndian.Uint32(data[certOffset : certOffset+4]))
	certType := binary.LittleEndian.Uint16(data[certOffset+6 : certOffset+8])
	return recordSize >= 8 && recordSize <= certSize && certType == 0x0002
}
