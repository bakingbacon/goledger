package ledger

// https://github.com/obsidiansystems/ledgerjs/blob/a81e68b01e13e4539e8ef9affbeb94b0fc197893/packages/hw-app-xtz/src/Tezos.js#L160
// tz1 signatures come correctly formatted from the ledger
// tz2 and tz3 signatures are in DER format from the ledger

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"regexp"

	"github.com/pkg/errors"
)

const HARDENED = 0x80000000

var matchSections = regexp.MustCompile(`/(\d+)([hH']?)`)

// EncodeBipPath takes a well-formatted BIP32 string path and converts it to a hex string
// Returns []byte on success, otherwise error
func encodeBipPath(path string) ([]byte, error) {

	// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
	// 44 references BIP44 policy; 1729 is Tezos 'coin'; Account and Change are remaining sections

	// Ex: /44'        /1729'      /0'         /0'
	//  04 80  00 00 2c 80  00 06 c1  80  00 00 00 80  00 00 00
	//  00 00  00 00 00 00  00 00 00  00  00 00 00
	// [ 4 128  0  0 44 128  0  6 193 128  0  0  0 128  0  0  0]

	// Explode path on each section
	sections := matchSections.FindAllStringSubmatch(path, 4)
	
	// Number of path components (ie: 'length'), hardcoded to 4
	var retPath string = "04"
	
	for _, section := range sections {

		if len(section) != 3 {
			return nil, errors.New("Not enough sections")
		}
		
		// Convert the numeric part of the section
		val, e := strconv.Atoi(section[1])
		if e != nil {
			return nil, e
		}
		
		if val >= HARDENED {
			return nil, errors.New("Invalid child index")
		}
		
		// Determine if last character of section is h, H, or '
		// indicating if this is "hardened" or not
		if section[2] == "h" || section[2] == "H" || section[2] == "'" {
			val = val + HARDENED
		} else if len(section[2]) != 0 {
			return nil, errors.New("Invalid modifier")
		}

		retPath = retPath + fmt.Sprintf("%08x", val)
	}

	bipPathBytes, err := hex.DecodeString(retPath)
	if err != nil {
		return nil, err
	}

	return bipPathBytes, nil
}

// Decodes a byte-slice representing a Bip32 path into a string representation.
// Does the opposite of encodeBipPath()
func DecodeBipPath(pathBytes []byte) (string, error) {

	// Get the number of path parts (ie: length)
	length := int(pathBytes[0])

	// 4 bytes per length + initial length byte
	if len(pathBytes) < 1 + length * 4 {
		return "", errors.New("Invalid Bip Path Length")
	}

	path := ""

	for i := 1; i < length * 4; i += 4 {
	
		v := binary.BigEndian.Uint32(pathBytes[i:i+4])
	
		h := ""
		if pathBytes[i] == 0x80 {
			h = "'"
			v = v - HARDENED
		}
		
		path += fmt.Sprintf("/%d%s", v, h)
	}
	
	return path, nil
}
