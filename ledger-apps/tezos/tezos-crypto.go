package tezos

import (
	"encoding/hex"
	"fmt"
	"github.com/Messer4/base58check"
	"github.com/pkg/errors"

	goledger "github.com/bakingbacon/goledger"
)

// These variables are specific to the Tezos Ledger library. They are used
// during the various B58 encode/decode processes for data returned from the device.
var (
	// For (de)constructing addresses
	tz1prefix goledger.Prefix = []byte{6, 161, 159}
	tz2prefix goledger.Prefix = []byte{6, 161, 161}
	tz3prefix goledger.Prefix = []byte{6, 161, 164}
	ktprefix  goledger.Prefix = []byte{2, 90, 121}

	edskprefix  goledger.Prefix = []byte{43, 246, 78, 7}
	edsigprefix goledger.Prefix = []byte{9, 245, 205, 134, 18}
	sigprefix   goledger.Prefix = []byte{4, 130, 43}

	edsk2prefix goledger.Prefix = []byte{13, 15, 58, 7}
	edpkprefix  goledger.Prefix = []byte{13, 15, 37, 217}
	edeskprefix goledger.Prefix = []byte{7, 90, 60, 179, 41}

	branchprefix      goledger.Prefix = []byte{1, 52}
	chainidprefix     goledger.Prefix = []byte{57, 52, 00}
	blockprefix       goledger.Prefix = []byte{1}
	endorsementprefix goledger.Prefix = []byte{2}
	genericopprefix   goledger.Prefix = []byte{3}
	networkprefix     goledger.Prefix = []byte{87, 82, 0}
)

// SignOperationOutput contains an operation with the signature appended, and the signature
type SignOperationOutput struct {
	SignedOperation string
	Signature       string
	EDSig           string
}

// Helper function to return the decoded signature
func decodeSignature(signature string) (string, error) {

	decBytes, err := base58check.Decode(signature)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode signature")
	}

	decodedSigHex := hex.EncodeToString(decBytes)

	// sanity
	if len(decodedSigHex) > 10 {
		decodedSigHex = decodedSigHex[10:]
	} else {
		return "", errors.Wrap(err, "decoded signature is invalid length")
	}

	return decodedSigHex, nil
}

func (t *TezosLedger) SignBlock(blockBytes, chainID string) (SignOperationOutput, error) {
	return t.signGeneric(blockprefix, blockBytes, chainID)
}

func (t *TezosLedger) SignSetDelegate(delegateBytes string) (SignOperationOutput, error) {
	return t.signGeneric(genericopprefix, delegateBytes, "")
}

func (t *TezosLedger) SignEndorsement(endorsementBytes, chainID string) (SignOperationOutput, error) {
	return t.signGeneric(endorsementprefix, endorsementBytes, chainID)
}

func (t *TezosLedger) SignNonce(nonceBytes string, chainID string) (SignOperationOutput, error) {
	return t.signGeneric(genericopprefix, nonceBytes, chainID)
}

func (t *TezosLedger) SignReveal(revealBytes string) (SignOperationOutput, error) {
	return t.signGeneric(genericopprefix, revealBytes, "")
}

func (t *TezosLedger) SignTransaction(trxBytes string) (SignOperationOutput, error) {
	return t.signGeneric(genericopprefix, trxBytes, "")
}

func (t *TezosLedger) signGeneric(opPrefix goledger.Prefix, incOpHex, chainID string) (SignOperationOutput, error) {

	// Base bytes of operation; all ops begin with prefix
	var opBytes = opPrefix

	if chainID != "" {

		// Strip off the network watermark (prefix), and then base58 decode the chain id string (ie: NetXUdfLh6Gm88t)
		chainIdBytes := goledger.B58cdecode(chainID, networkprefix)
		//fmt.Println("ChainIDByt: ", chainIdBytes)
		//fmt.Println("ChainIDHex: ", hex.EncodeToString(chainIdBytes))

		opBytes = append(opBytes, chainIdBytes...)
	}
	
	// Decode the incoming operational hex to bytes
	incOpBytes, err := hex.DecodeString(incOpHex)
	if err != nil {
		return SignOperationOutput{}, errors.Wrap(err, "failed to sign operation")
	}
	//fmt.Println("IncOpHex:   ", incOpHex)
	//fmt.Println("IncOpBytes: ", incOpBytes)

	// Append incoming op bytes to either prefix, or prefix + chainId
	opBytes = append(opBytes, incOpBytes...)
	//fmt.Println("ToSignBytes: ", opBytes)
	//fmt.Println("ToSignByHex: ", hex.EncodeToString(opBytes))

	edSignature, err := t.SignBytes(opBytes) // returns edsig... (string)
	if err != nil {
		return SignOperationOutput{}, errors.Wrap(err, "failed signer")
	}

	// Decode out the signature from the operation
	decodedSig, err := decodeSignature(edSignature)
	if err != nil {
		return SignOperationOutput{}, errors.Wrap(err, "failed to decode signed block")
	}
	//fmt.Println("DecodedSign: ", decodedSig)

	return SignOperationOutput{
		SignedOperation: fmt.Sprintf("%s%s", incOpHex, decodedSig),
		Signature: decodedSig,
		EDSig: edSignature,
	}, nil
}


// Helper function to convert a public key to a public key hash
func pkhFromPkBytes(pk []byte) (string, error) {

	// PKH needs only 20 byte buffer
	pkh, err := goledger.Blake2b(pk, 20)
	if err != nil {
		return "", err
	}

	return goledger.B58cencode(pkh, tz1prefix), nil
}
