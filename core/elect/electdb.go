package elect

import (
	"encoding/binary"
	"github.com/cloudcan/go-ethereum/common"
	"github.com/cloudcan/go-ethereum/ethdb"
	"github.com/cloudcan/go-ethereum/log"
	"github.com/cloudcan/go-ethereum/rlp"
	"github.com/cloudcan/go-ethereum/trie"
)

const (
	delegateKey = "delegate_"
)

// elect database
type ElectDB struct {
	db            ethdb.Database
	delegates     []common.Address
	candidateTire *trie.SecureTrie
	tireDB        *trie.Database
}

func (db *ElectDB) Root() common.Hash {
	return db.candidateTire.Hash()
}

// 添加委托人
func (db *ElectDB) AddDelegates(delegates ...common.Address) error {
	bytes, err := rlp.EncodeToBytes(delegates)
	if err != nil {
		log.Error("无法进行rlp编码", "err", err)
		return err
	}
	if db.db.Put([]byte(delegateKey), bytes) != nil {
		log.Error("保存代表出错", "err", err)
		return err
	}
	db.delegates = append(db.delegates, delegates...)
	for _, delegate := range delegates {
		err = db.AddCandidate(Candidate{
			Votes: 0,
			Addr:  delegate,
		})
		if err != nil {
			log.Error("添加候选者出错", "err", err)
			return err
		}
	}
	return nil
}
func (db *ElectDB) AddCandidate(candidate Candidate) error {
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, candidate.Votes)
	return db.candidateTire.TryUpdate(candidate.Addr.Bytes(), value)
}

// create new elect database
func New(db ethdb.Database, candidateRoot common.Hash) (*ElectDB, error) {
	tireDB := trie.NewDatabase(db)
	candidateTire, err := trie.NewSecure(candidateRoot, tireDB)
	if err != nil {
		log.Error("create elect database failed", "err", err)
		return nil, err
	}
	bytes, err := db.Get([]byte(delegateKey))
	var delegates []common.Address
	if err == nil {
		_ = rlp.DecodeBytes(bytes, &delegates)
	}
	return &ElectDB{
		db:            db,
		tireDB:        tireDB,
		candidateTire: candidateTire,
		delegates:     delegates,
	}, nil
}
func (db *ElectDB) Commit() (common.Hash, error) {
	root, err := db.candidateTire.Commit(nil)
	_ = db.tireDB.Commit(root, true)
	return root, err
}

func (db *ElectDB) GetDelegates() []common.Address {
	return db.delegates
}

type Candidate struct {
	Votes uint64
	Addr  common.Address
}
type Candidates []Candidate

func (c Candidates) Len() int {
	return len(c)
}

func (c Candidates) Less(i, j int) bool {
	return c[i].Votes < c[j].Votes
}

func (c Candidates) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (db *ElectDB) GetCandidates() Candidates {
	iterator := trie.NewIterator(db.candidateTire.NodeIterator(nil))
	candidates := make([]Candidate, 0)
	for {
		if iterator.Next() {
			addr := common.BytesToAddress(iterator.Key)
			votes := binary.BigEndian.Uint64(iterator.Value)
			candidates = append(candidates, Candidate{
				Votes: votes,
				Addr:  addr,
			})
		} else {
			break
		}
	}
	return candidates
}
