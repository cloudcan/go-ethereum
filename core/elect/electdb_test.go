package elect

import (
	"github.com/cloudcan/go-ethereum/common"
	"github.com/cloudcan/go-ethereum/core/rawdb"
	"github.com/cloudcan/go-ethereum/params"
	"testing"
)

func TestElectDB_AddCandidate(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	electDB, err := New(db, common.Hash{})
	if err != nil {
		t.Error("create elect db failed", err)
	}
	_ = electDB.AddDelegates(params.MainnetChainConfig.Dpos.Delegates...)
	hashes, err := electDB.Commit()
	electDB2, err := New(db, hashes)
	root := electDB2.Root()
	if hashes != root {
		t.Fail()
	}
}
