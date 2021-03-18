package tezos

const (
	CLA  uint8  = 0x80 // Always the same for every APDU call

	// APDU Instructions
	// https://github.com/LedgerHQ/app-tezos/blob/master/APDUs.md
	Version           uint8 = 0x00 // Get version information for the ledger
	AuthBaking        uint8 = 0x01 // Authorize baking
	GetPubKey         uint8 = 0x02 // Get the ledger’s internal public key
	PromptPubKey      uint8 = 0x03 // Prompt for the ledger’s internal public key
	SignBytes         uint8 = 0x04 // Sign a message with the ledger's key
	SignUnsafeBytes   uint8 = 0x05 // Sign a message with the ledger's key (no hash)
	ResetHLW          uint8 = 0x06 // Reset baking high-level watermarks
	GetAuthKey        uint8 = 0x07 // Get the current authorized baking key
	GetMainHWM        uint8 = 0x08 // TODO Get current high water mark
	CommitHash        uint8 = 0x09 // Get the commit hash
	BakingSetup       uint8 = 0x0a // Setup a baker with chainId, high-level watermarks, bip pathh
	GetBakingHLW      uint8 = 0x0b // Get the current high-level watermarks
	DeauthBaking      uint8 = 0x0c // Deauthorize baking
	QueryBakingKey    uint8 = 0x0d // Get the current authorized baking key
	GetHMAC           uint8 = 0x0e // TODO Get the HMAC of a message
	SignBytesWithHash uint8 = 0x0f // Sign a message with the ledger's key (with hash)
)

// This struct represents the data to be encoded and sent to the device.
// The following 2 components of the APDU are either static, or calculated at run-time
//	CLA   uint8    // Instruction class (always 0x80)
//	LC    uint8    // Length of CDATA (Calculated during marshaling)
// TzApdu implements the ledger.Apdu interface
type TzApdu struct {
	INS   uint8    // Instruction code (0x00-0x0f)
	P1    uint8    // Message sequence (0x00 = first, 0x81 = last, 0x01 = other)
	P2    uint8    // Derivation type (0=ED25519, 1=SECP256K1, 2=SECP256R1, 3=BIPS32_ED25519)
	CDATA []uint8  // Variable length data depending on INS
}

// Encodes a TzApdu struct as needed by the Tezos Ledger wallet app for writing to the device
func (a TzApdu) MarshalBinary() ([]byte, error) {

	var bbytes = make([]byte, 5)
	bbytes[0] = CLA
	bbytes[1] = a.INS
	bbytes[2] = a.P1
	bbytes[3] = a.P2
	
	// Length of CDATA
	bbytes[4] = byte(len(a.CDATA))
	
	// CDATA is variable length, so append/grow
	bbytes = append(bbytes, a.CDATA...)

	return bbytes, nil
}
