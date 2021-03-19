package tezos

import (
	"fmt"
	"strings"
	"testing"
	"os"
)

const (
	CUR_VER  = "2.2.9"
	CUR_HASH = "b28c2364"
)

var tledger *TezosLedger

func TestMain(m *testing.M) {

	var err error

	// Get device
	tledger, err = Get()
	if err != nil {
		fmt.Printf("Cannot get Ledger device: %s\n", err)
		os.Exit(1)
	}
	defer tledger.Close()

	os.Exit(m.Run())
}

func TestGetVersion(t *testing.T) {

	ver, err := tledger.GetVersion()
	if err != nil {
		t.Errorf("Cannot get version: %s\n", err)
	}

	if !strings.HasSuffix(string(ver), CUR_VER) {
		t.Errorf("Expecting %s; Got %s", CUR_VER, string(ver))
	}
}

func TestGetCommitHash(t *testing.T) {

	commitHash, err := tledger.GetCommitHash()
	if err != nil {
		t.Errorf("Cannot get commit hash: %s\n", err)
	}
	
	if !strings.HasPrefix(commitHash, CUR_HASH) {
		t.Errorf("Expecting '%s'; Got %s", CUR_HASH, commitHash)
	}
}
