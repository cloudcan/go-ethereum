package dpos

import (
	"bytes"
	"errors"
	"github.com/cloudcan/go-ethereum/accounts"
	"github.com/cloudcan/go-ethereum/common"
	"github.com/cloudcan/go-ethereum/consensus"
	"github.com/cloudcan/go-ethereum/core/elect"
	"github.com/cloudcan/go-ethereum/core/rawdb"
	"github.com/cloudcan/go-ethereum/core/state"
	"github.com/cloudcan/go-ethereum/core/types"
	"github.com/cloudcan/go-ethereum/crypto"
	"github.com/cloudcan/go-ethereum/ethdb"
	"github.com/cloudcan/go-ethereum/params"
	"github.com/cloudcan/go-ethereum/rlp"
	"github.com/cloudcan/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
	"sort"
	"sync"
)

const (
	SigntureCacheSize = 255
	GasLimit          = 8e6
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// dpos consensus engine
// implements consensus.Engine interface
type Dpos struct {
	db       ethdb.Database
	config   params.DposConfig
	sigcache *lru.ARCCache
	electdb  *elect.ElectDB
	lock     sync.RWMutex
	signer   common.Address
	signFn   SignerFn
}

// create new dpos consensus engine
func New(config params.DposConfig, db ethdb.Database) *Dpos {
	sigcache, _ := lru.NewARC(SigntureCacheSize)
	hash := rawdb.ReadHeadHeaderHash(db)
	number := rawdb.ReadHeaderNumber(db, hash)
	header := rawdb.ReadHeader(db, hash, *number)
	electdb, _ := elect.New(db, header.CandidateRoot)
	return &Dpos{
		db:       db,
		config:   config,
		sigcache: sigcache,
		electdb:  electdb,
	}
}

// get block witness
func (d *Dpos) Author(header *types.Header) (common.Address, error) {
	return d.ecrecover(header, d.sigcache)
}

func (d *Dpos) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

func (d *Dpos) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (d *Dpos) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

func (d *Dpos) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// 验证出块时间
	genesis := chain.GetHeaderByNumber(0)
	if header.Time < genesis.Time || (header.Time-genesis.Time)%d.config.BlockInterval != 0 {
		return errors.New("错误的出块时间")
	}
	// 验证出块资格
	offset := (header.Time - genesis.Time) / d.config.BlockInterval % d.config.DelegateCount
	d.lock.RLock()
	witness := d.signer
	d.lock.RUnlock()
	if len(d.getDelegates()) != int(d.config.DelegateCount) || d.getDelegates()[offset] != witness {
		return errors.New("没有出块资格")
	}
	return nil
}

func (d *Dpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction) {
	return
}
func (d *Dpos) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate the rewards for the witness
	d.lock.RLock()
	witness := d.signer
	d.lock.RUnlock()
	state.AddBalance(witness, big.NewInt(int64(d.config.BlockReward)))
	header.Root = state.IntermediateRoot(false)
	//
	genesis := chain.GetHeaderByNumber(0)
	if (header.Time-genesis.Time)%d.config.Period == 0 {
		// 进行新一轮选举
		candidates := d.electdb.GetCandidates()
		sort.Sort(candidates)
		_ = sort.Reverse(candidates)
		for i := uint64(0); i < d.config.DelegateCount; i++ {
			_ = d.electdb.AddDelegates(candidates[i].Addr)
		}
	}
	root, _ := d.electdb.Commit()
	header.CandidateRoot = root
	return types.NewBlock(header, txs, receipts), nil
}

func (d *Dpos) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	// Don't hold the signer fields for the entire sealing procedure
	d.lock.RLock()
	signFn := d.signFn
	signer := d.signer
	d.lock.RUnlock()
	buffer := new(bytes.Buffer)
	encodeSigHeader(buffer, header)
	sig, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeDpos, buffer.Bytes())
	if err != nil {
		return err
	}
	header.WitnessSignature = sig
	select {
	case results <- block.WithSeal(header):
		return nil
	case <-stop:
		return errors.New("seal be stopped")
	}
}

func (d *Dpos) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}
func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra, // Yes, this will panic if extra is too short
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}
func (d *Dpos) APIs(chain consensus.ChainReader) []rpc.API {
	return nil
}

func (d *Dpos) Close() error {
	return nil
}

func (d *Dpos) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// TODO verifyHeader

	return nil
}

func (d *Dpos) getDelegates() []common.Address {
	return d.electdb.GetDelegates()
}

func (d *Dpos) Authorize(signer common.Address, signFn SignerFn) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.signer = signer
	d.signFn = signFn
}

// ecrecover extracts the Ethereum account address from a signed header.
func (d *Dpos) ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(d.SealHash(header).Bytes(), header.WitnessSignature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}
