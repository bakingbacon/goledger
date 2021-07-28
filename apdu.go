package ledger

import (
	"bytes"
	"context"
	"encoding/binary"
	_ "encoding/hex"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrMoreData = errors.New("Not enough data")
)

// Interface to be implemented by sub-libraries, as the APDU struct will be
// specific to each ledger application. This interface enforces the one required
// function that 'Write' must call.
type Apdu interface {
	MarshalBinary() ([]byte, error)
}

// Writes data to the device. Accepts an Apdu struct pointer. It marshals a
// binary representation of APDU instruction, wraps the command according to
// Ledger binary protocol then writes the resulting bytes to the device.
// Returns number of bytes written to the device which will be far greater
// than the bytes of the Apdu struct due to padding/wrapping.
func (l *Ledger) Write(apdu Apdu, channel []byte) (int, error) {

	prefix := []byte{0}

	apduBytes, err := apdu.MarshalBinary()
	if err !=  nil {
		return 0, errors.New("Unable to marshal APDU instruction")
	}
	//fmt.Println("HID =>", hex.EncodeToString(apduBytes))

	// Encode instruction + parameters
	bufferBytes, err := l.wrapCommandAPDU(channel, apduBytes, 64)
	if err != nil {
		return 0, errors.Wrap(err, "Unable to wrap APDU instruction")
	}
	bufferBytes = append(prefix, bufferBytes...)
	//fmt.Printf("Wrapped: %v (%d)\n", hex.EncodeToString(bufferBytes), len(bufferBytes))

	// Write to device
	b, err := l.Dev.Write(bufferBytes)
	if b <= 0 {
		return 0, errors.Wrap(err, "Failed to write")
	}
	//fmt.Println("Wrote bytes:", b)
	
	return b, nil
}

// Reads bytes from the device's buffer, decodes the result and
// checks for internal errors.
// Returns byte slice or error
func (l *Ledger) Read(channel []byte) ([]byte, error) {

	var result []byte           // Holds raw bytes read from device
	var unwrappedResult []byte  // Holds unwrapped/parsed result

	// Helper function for reading 64 byte responses
	readData := func() ([]byte, error) {

		ctx, cancel := context.WithTimeout(context.Background(), 50 * time.Second)
		defer cancel()

		var err error
		var r = make([]byte, 64)

		// Implements a waiter for first response from device
		// If num bytes read is 0, sleep for a bit then try again
		// After we read, we can return
		for b := 0; b == 0; {
			
			// Read from device
			b, err = l.Dev.Read(r)
			if b < 0 {
				return nil, errors.Wrap(err, "Failed to read")
			}
			
			// If no bytes read, sleep  and repeat
			if b == 0 {
				select{
				case <-ctx.Done():
					return nil, errors.New("Timeout Expired")
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
		}
		
		// Return what was read
		return r, nil
	}

	// Read initial bytes
	firstBytes, err := readData()
	if err != nil {
		return nil, err
	}
	result = append(result, firstBytes...)

	// Decode initial result
	// loop in case more data needs to be fetched
	for moreData := true; moreData; {

		unwrappedResult, err = l.unwrapResponseAPDU(channel, result, 64)
		if err != nil {

			// Is more data needed?
			if errors.Is(err, ErrMoreData) {

				// Read another 64 bytes from device
				moreBytes, err := readData()
				if err != nil {
					return nil, err
				}

				// Append additional data to main slice; loop and unwrap again
				result = append(result, moreBytes...)

			} else {

				// Some other error while unwrapping
				return nil, errors.Wrap(err, "Failed to decode response")
			}

		} else {
			
			// No errors; no additional data to read; break loop
			moreData = false
		}
	}

//	fmt.Println("DecodedBytesLen:", len(unwrappedResult))
//	fmt.Println("DecodedBytes:   ", unwrappedResult)
//	fmt.Println("DecodedHex:     ", hex.EncodeToString(unwrappedResult))
	
	return unwrappedResult, nil
}

//
// https://github.com/LedgerHQ/blue-loader-python/blob/bb7aeade0a7eed0c61a57482abc18cca9e97b253/ledgerblue/ledgerWrapper.py#L23
func (l *Ledger) wrapCommandAPDU(channel []byte, command []byte, packetSize int) ([]byte, error) {

	if packetSize < 3 {
		return nil, errors.New("Can't handle less than 3 bytes")
	}
	
	var sequenceIdx uint16 = 0		
	offset := 0	
	extraHeaderSize := 2

	// byte array
	var result = make([]byte, 0)

	// Add channel
	result = append(result, channel...)

	// Tag
	result = append(result, []byte{5}...)
	
	// Sequence
	var seqIdxBytes = make([]byte, 2)
	binary.BigEndian.PutUint16(seqIdxBytes, sequenceIdx)
	result = append(result, seqIdxBytes...)

	// Length
	var lenBytes = make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(command)))
	result = append(result, lenBytes...)

	sequenceIdx = sequenceIdx + 1
	
	blockSize := len(command)
	if len(command) > packetSize - 5 - extraHeaderSize {
		blockSize = packetSize - 5 - extraHeaderSize
	}
	
	result = append(result, command[offset : offset + blockSize]...)
	offset = offset + blockSize

	for ; offset != len(command); {

		result = append(result, channel...)
		
		// Tag
		result = append(result, []byte{5}...)

		// Sequence
		var seqIdxBytes = make([]byte, 2)
		binary.BigEndian.PutUint16(seqIdxBytes, sequenceIdx)
		result = append(result, seqIdxBytes...)
		
		sequenceIdx = sequenceIdx + 1
		
		blockSize = len(command) - offset
		if (len(command) - offset) > packetSize - 3 - extraHeaderSize {
			blockSize = packetSize - 3 - extraHeaderSize
		}

		result = append(result, command[offset : offset + blockSize]...)
		offset = offset + blockSize
	}

	// Ledger Nano's, etc, need suffix padding
	for ; (len(result) % packetSize) != 0; {
		result = append(result, []byte{0}...)
	}

	return result, nil
}

//
// https://github.com/LedgerHQ/blue-loader-python/blob/bb7aeade0a7eed0c61a57482abc18cca9e97b253/ledgerblue/ledgerWrapper.py#L58
func (l *Ledger) unwrapResponseAPDU(channel []byte, data []byte, packetSize int) ([]byte, error) {

	sequenceIdx := 0
	offset := 0
	extraHeaderSize := 2

	if len(data) == 0 || (len(data) < 5 + extraHeaderSize + 5) {
		return nil, errors.New("No data")
	}

	// Unpack channel and compare
	packedChannel := data[offset:offset+2]
	if bytes.Compare(packedChannel, channel) != 0 {
		return nil, errors.New("Invalid channel")
	}

	offset = offset + 2

	// Check tag
	packedTag := []byte{data[offset]}
	if bytes.Compare(packedTag, []byte{5}) != 0 {
		return nil, errors.New("Invalid tag")
	}

	offset = offset + 1

	// Check sequence
	packedSeq := int(binary.BigEndian.Uint16(data[offset:offset+2]))
	if packedSeq != sequenceIdx {
		return nil, errors.New("Invalid sequence")
	}

	offset = offset + 2

	// Length of response is encoded
	responseLength := int(binary.BigEndian.Uint16(data[offset:offset+2]))
	
	//fmt.Printf("RL: %d / DA: %d\n", responseLength, len(data))

	offset = offset + 2
	
	if len(data) < 5 + extraHeaderSize + responseLength {
		return nil, ErrMoreData
	}

	blockSize := responseLength
	if responseLength > packetSize - 5 - extraHeaderSize {
		blockSize = packetSize - 5 - extraHeaderSize
	}

	result := data[offset:offset+blockSize]
	offset = offset + blockSize

	// loop over data
	for ; len(result) < responseLength; {

		sequenceIdx = sequenceIdx + 1

		if offset == len(data) {
			return nil, errors.New("No data")
		}

		// Unpack channel in this sequence and compare
		packedChan := data[offset:offset+2]
		if bytes.Compare(packedChan, channel) != 0 {
			return nil, errors.New("Invalid channel")
		}

		offset = offset + 2

		// Check tag
		packedTag := []byte{data[offset]}
		if bytes.Compare(packedTag, []byte{5}) != 0 {
			return nil, errors.New("Invalid tag")
		}
		
		offset = offset + 1
		
		// Check sequence
		packedSeq := int(binary.BigEndian.Uint16(data[offset:offset+2]))
		if packedSeq != sequenceIdx {
			return nil, errors.New("Invalid sequence")
		}

		offset = offset + 2
		
		blockSize := responseLength - len(result)
		if (responseLength - len(result)) > packetSize - 3 - extraHeaderSize {
			blockSize = packetSize - 3 - extraHeaderSize
		}
		result = append(result, data[offset:offset+blockSize]...)
		offset = offset + blockSize
	}

	// End of decoding; check for errors
	swOffset := len(result) - 2
	
	sw := (int(result[swOffset]) << 8) + int(result[swOffset + 1])
	if err := checkFailure(sw); err != nil {
		return nil, err
	}

	// Actual result strips off trailing status code
	result = result[:swOffset]

	return result, nil
}


func checkFailure(code int) error {

	// https://github.com/LedgerHQ/ledgerjs/blob/ebfc7ebb497b2c1a435974e2d5e3e6097bc1cf1e/packages/errors/src/index.ts#L241
	// https://www.eftlab.co.uk/knowledge-base/complete-list-of-apdu-responses/

	if code != 0x9000 && ((code & 0xFF00) != 0x6100) {
		switch code {
		case 0x6484:
			return errors.New("Are you using the correct targetId?")
		case 0x6982:
			return errors.New("Have you uninstalled the existing CA with resetCustomCA first?")
		case 0x6985:
			return errors.New("Operation denied by the user")
		case 0x6a80:
			return errors.New("Level is below safety watermark")
		case 0x6a84:
		case 0x6a85:
			return errors.New("Not enough space?")
		case 0x6a83:
			return errors.New("Maybe this app requires a library to be installed first?")
		case 0x6b00:
			return errors.New("Incorrect parameters received P1/P2")
		case 0x6c00:
			return errors.New("Wrong length")
		case 0x6c66:
			return errors.New("Operation not allowed")
		case 0x6d00:
			return errors.New("Unsupported Instruction")
		case 0x6e00:
			return errors.New("Unexpected state of device: verify that the right application is opened?")
		case 0x6f00:
			return errors.New("Internal technical problem")
		case 0x917e:
			return errors.New("Length of command string invalid")
		case 0x9405:
			return errors.New("Parse error")
		default:
			return fmt.Errorf("Unknown status 0x%02x", code)
		}
	}
	
	return nil
}
