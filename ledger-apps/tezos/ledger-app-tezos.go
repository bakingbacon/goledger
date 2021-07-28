// Package tezos is a sub-module for the parent ledger package.
// This module provides an interface to the various application
// features and functions provided by the Tezos Wallet and Tezos
// Baking Ledger applications.
package tezos

import (
	"encoding/binary"
	_ "encoding/hex"
	"fmt"

	"github.com/pkg/errors"

	ledger "github.com/bakingbacon/goledger"
)

// The main difference between SignBytes and SignUnsafeBytes is that SignUnsafeBytes skips the
// parsing step which shows what operation is included in the APDU data. This is unsafe,
// because the user doesn’t see what operation they are actually signing. When this happens,
// the device displays "Unrecognized: Sign Hash" so that they can make appropriate external
// steps to verify this hash.
// 
// The difference between SignBytes and SignBytesWithHash is that the latter returns both
// the signature AND the hash of the data (while the former only returns the signature).
const (
	LEDGER_VENDOR    uint16 = 11415
	LEDGER_PRODUCTID uint16 = 1
	LEDGER_USAGEPAGE uint16 = 65440
	LEDGER_IFACENUM  uint16 = 0

	MAINNET_CHAINID  uint32 = 0x7A06A770 // Tezos mainnet NetXdQprcVkpaWU
)

var (
	TEZOS_CHANNEL = []byte{1, 1}

	ErrLengthZero     = errors.New("Returned no data")
	ErrLengthMismatch = errors.New("Returned data length mismatch")
	ErrDecodeLength   = errors.New("Unable to decode length")
)

// TezosLedger is just a localized embedded struct of the parent
// 'Ledger' struct. This way we can access all of the parent functions
// along with implementing functions specific to the Tezos ledger app
type TezosLedger struct {
	*ledger.Ledger
}

// Use the HID library to establish a connection to the ledger device. The
// device will not appear to the USB subsystem until the ledger is unlocked
// by entering the PIN code
func Get() (*TezosLedger, error) {

	tezos, err := ledger.Get(LEDGER_VENDOR, LEDGER_PRODUCTID, LEDGER_IFACENUM, LEDGER_USAGEPAGE)
	if err != nil {
		return nil, err
	}
	return &TezosLedger{
		tezos,
	}, nil
}

// Instructs the HID library to close USB communications
func (l *TezosLedger) Close() {
	l.Dev.Close()
}

// Returns a version string of the currently open app
// Ex: Baking 2.2.1
func (l *TezosLedger) GetVersion() (string, error) {

	apdu := &TzApdu{
		Version,
		0x00,
		0x00,
		nil,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to get version")
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to get version")
	}

	// https://github.com/LedgerHQ/app-tezos/blob/master/src/version.h
	class := "Wallet"
	if resp[0] == 1 {
		class = "Baking"
	}
	verStr := fmt.Sprintf("%s %d.%d.%d", class, resp[1], resp[2], resp[3])

	return verStr, nil
}

// Returns the git commit hash of the currently open app
// Ex: 'b28c2364'
func (l *TezosLedger) GetCommitHash() (string, error) {

	apdu := &TzApdu{
		CommitHash,
		0x00,
		0x00,
		nil,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to write commit hash")
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to get commit hash")
	}

	return string(resp), nil
}

// Prompts user to confirm the public key (edpk...), and public key hash (tz1..) of the currently set BipPath
// Use SetBipPath() before calling this function.
func (l *TezosLedger) GetPublicKeyWithPrompt() (string, string, error) {
	return l.getKey(PromptPubKey)
}

// Returns the public key (edpk...), and public key hash (tz1..) of the currently set BipPath
// Use SetBipPath() before calling this function.
func (l *TezosLedger) GetPublicKey() (string, string, error) {
	return l.getKey(GetPubKey)
}

// Internal helper function to retrieve public key from device.
func (l *TezosLedger) getKey(ins uint8) (string, string, error) {

	if len(l.BipPath) == 0 {
		return "", "", errors.New("No BIP Path is set; Use SetBipPath()")
	}

	apdu := &TzApdu{
		ins,
		0x00,
		0x00,
		l.BipPath,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", "", errors.Wrap(err, "Unable to write key request")
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", "", errors.Wrap(err, "Unable to read key request")
	}

	// First byte is length info
	_respLength, bRead := binary.Uvarint(resp[:1])
	if bRead != 1 {
		return "", "", ErrDecodeLength
	}
	respLength := int(_respLength)  // Convert from uint64

	// Check if lengths match what ledger tells us
	if respLength != len(resp[1:]) {
		return "", "", ErrLengthMismatch
	}

	// Nothing returned? Bail
	if respLength == 0 {
		return "", "", ErrLengthZero
	}

	// No idea what the 0x02 value at resp[1] is for, but definitely
	// not part of the key and not part of the length check. Ignore it.

	// PK comes directly from device without prefix/watermark
	pk := ledger.B58cencode(resp[2:], edpkprefix)

	// Convert PK to PKH
	pkh, err := pkhFromPkBytes(resp[2:])
	if err != nil {
		return pk, "", err
	}

	return pk, pkh, nil
}

// Setup ledger to bake on a specific chain, starting at a specific high-level watermark,
// and using the current bip path.
// Use SetBipPath() before calling this function.
// Returns the authorized public key (edpk...), and public key hash (tz1..), or error
func (l *TezosLedger) SetupBaking(chainId string, hlwm int) (string, string, error) {

	if len(l.BipPath) == 0 {
		return "", "", errors.New("No BIP Path is set; Use SetBipPath()")
	}
	//fmt.Println(l.BipPath)

	// Need to b58cdecode the chainId
	chainIdBytes := ledger.B58cdecode(chainId, networkprefix)

	// Encode high-level watermark
	var hlwmBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(hlwmBytes, uint32(hlwm))

	// Build CDATA
	cdata := chainIdBytes
	cdata = append(cdata, hlwmBytes...) // main hlwm
	cdata = append(cdata, hlwmBytes...) // test hlwm
	cdata = append(cdata, l.BipPath...)

	// Build APDU
	apdu := &TzApdu{
		BakingSetup,
		0x00,
		0x00,
		cdata,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", "", err
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", "", errors.Wrap(err, "Unable to read baking setup response")
	}

	// First byte is length info
	respLength, bRead := binary.Uvarint(resp[:1])
	if bRead != 1 {
		return "", "", ErrDecodeLength
	}

	if int(respLength) != len(resp[1:]) {
		return "", "", ErrLengthMismatch
	}

	// No idea what the 0x02 value at resp[1] is for, but definitely
	// not part of the key and not part of the length check. Ignore it.

	// PK comes directly from device without prefix/watermark
	pk := ledger.B58cencode(resp[2:], edpkprefix)

	// Convert PK to PKH
	pkh, err := pkhFromPkBytes(resp[2:])
	if err != nil {
		return pk, "", err
	}

	return pk, pkh, nil
}

// Authorizes the current BipPath address to sign block and endorsement operations.
// Use SetBipPath() before calling this function.
// Returns the authorized public key (edpk...), and public key hash (tz1..), or error
func (l *TezosLedger) AuthorizeBaking() (string, string, error) {

	if len(l.BipPath) == 0 {
		return "", "", errors.New("No BIP Path is set; Use SetBipPath()")
	}

	apdu := &TzApdu{
		AuthBaking,
		0x00,
		0x00,
		l.BipPath,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", "", err
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", "", errors.Wrap(err, "Unable to read auth request")
	}

	// First byte is length info
	respLength, bRead := binary.Uvarint(resp[:1])
	if bRead != 1 {
		return "", "", ErrDecodeLength
	}

	if int(respLength) != len(resp[1:]) {
		return "", "", ErrLengthMismatch
	}

	// No idea what the 0x02 value at resp[1] is for, but definitely
	// not part of the key and not part of the length check. Ignore it.

	pk := ledger.B58cencode(resp[2:], edpkprefix)

	// Convert PK to PKH
	pkh, err := pkhFromPkBytes(resp[2:])
	if err != nil {
		return pk, "", err
	}

	return pk, pkh, nil
}

// Removes the ability to sign baking/endorsements
// Returns nothing on success, error otherwise
func (l *TezosLedger) DeauthorizeBaking() error {

	apdu := &TzApdu{
		DeauthBaking,
		0x00,
		0x00,
		nil,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return err
	}

	_, err = l.Read(TEZOS_CHANNEL)
	if err != nil {
		return errors.Wrap(err, "Unable to read deauth reply")
	}

	// Returns nothing if successful
	return nil
}

// Reset all watermarks to a given level. User must allow this action on device.
// Returns nothing on success, error otherwise
func (l *TezosLedger) ResetBakingHLW(newLevel int) error {

	var b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(newLevel))

	apdu := &TzApdu{
		ResetHLW,
		0x00,
		0x00,
		b,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return err
	}

	_, err = l.Read(TEZOS_CHANNEL)
	if err != nil {
		return errors.Wrap(err, "Unable to read reset HLW reply")
	}

	// Returns nothing if successful
	return nil
}

// Query all watermarks
// Returns current watermarks for main and test chain, along with main chain id
func (l *TezosLedger) GetBakingSetup() (uint32, uint32, string, error) {

	apdu := &TzApdu{
		GetBakingHLW,
		0x00,
		0x00,
		nil,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return 0, 0, "", err
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return 0, 0, "", errors.Wrap(err, "Unable to read HLW reply")
	}

	if len(resp) < 12 {
		return 0, 0, "", errors.New("Not enough data returned")
	}

	// First 4 bytes, uint32 HLW of main chain
	mainWM := binary.BigEndian.Uint32(resp[:4])

	// Second 4 bytes, uint32 HLW of test chain
	testWM := binary.BigEndian.Uint32(resp[4:8])

	// Last 4 bytes, hex-bytes of main chain id without prefix
	// B58 encode with proper prefix
	chainId := ledger.B58cencode(resp[8:12], networkprefix)

	return mainWM, testWM, chainId, nil
}

// Returns the Bip32 key path of the currently authorized baking address
func (l *TezosLedger) GetAuthorizedKeyPath() (string, error) {

	apdu := &TzApdu{
		GetAuthKey,
		0x00,
		0x00,
		nil,
	}

	_, err := l.Write(apdu, TEZOS_CHANNEL)
	if err != nil {
		return "", err
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to read auth request")
	}

	// Ex: [4 128 0 0 44 128 0 6 193 128 0 0 0 128 0 0 0]
	bipPath, err := ledger.DecodeBipPath(resp)
	if err != nil {
		return "", err
	}

	return bipPath, nil
}

// Generic signing function. Bakes, nonces, and endorsements cannot be signed by the wallet
// app, and generic messages cannot be signed by the baking app.
// Device will sign the given bytes using the registered bip path
// Use SetBipPath() before calling this function
// Returns signature of signed bytes or error
func (l *TezosLedger) SignBytes(bytesToSign []byte) (string, error) {

	// Signing endorsement/bytes requires first sending a signing request
	// with the BIP32 path to use, followed by a second APDU containing
	// another signing request with the endorsement bytes.
	//
	// Perform back-to-back write/reads
	//

	if len(l.BipPath) == 0 {
		return "", errors.New("No BIP Path is set; Use SetBipPath()")
	}

	signingApdu := &TzApdu{
		SignBytes,
		0x00,
		0x00,
		l.BipPath,
	}

	_, err := l.Write(signingApdu, TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to sign bytes (1)")
	}

	resp, err := l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to read bytes signature (1)")
	}
	//fmt.Println("S1_RESP:", resp)
	//fmt.Println()

	// Part 2
	signBytesApdu := &TzApdu{
		SignBytes,
		0x81,
		0x00,
		bytesToSign,
	}

	if r, err := l.Dev.SetNonBlocking(false); r == -1 {
		return "", errors.Wrap(err, "Could not set non-blocking")
	}

	_, err = l.Write(signBytesApdu, TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to sign bytes (2)")
	}

	resp, err = l.Read(TEZOS_CHANNEL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to read bytes signature")
	}

	if r, err := l.Dev.SetNonBlocking(true); r == -1 {
		return "", errors.Wrap(err, "Could not set non-blocking")
	}

	//fmt.Println(resp)
	//fmt.Println(hex.EncodeToString(resp))

	// What returns from the ledger is the raw bytes of the signature.
	// Need to b58cencode(rawBytes, prefix.edsig) to see human-readable signature
	return ledger.B58cencode(resp, edsigprefix), nil
}
