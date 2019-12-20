package wallet

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// NewConcurrentDownloader creates ConcurrentDownloader instance.
func NewConcurrentDownloader(ctx context.Context) *ConcurrentDownloader {
	runner := NewAtomicGroup(ctx)
	result := &Result{}
	return &ConcurrentDownloader{runner, result}
}

type ConcurrentDownloader struct {
	*AtomicGroup
	*Result
}

type Result struct {
	mu          sync.Mutex
	transfers   []Transfer
	blocks      []*big.Int
	blockRanges [][]*big.Int
}

func (r *Result) Push(transfers ...Transfer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transfers = append(r.transfers, transfers...)
}

func (r *Result) Get() []Transfer {
	r.mu.Lock()
	defer r.mu.Unlock()
	rst := make([]Transfer, len(r.transfers))
	copy(rst, r.transfers)
	return rst
}

func (r *Result) PushBlock(block *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.blocks = append(r.blocks, block)
}

func (r *Result) GetBlocks() []*big.Int {
	r.mu.Lock()
	defer r.mu.Unlock()
	rst := make([]*big.Int, len(r.blocks))
	copy(rst, r.blocks)
	return rst
}

func (r *Result) PushRange(blockRange []*big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.blockRanges = append(r.blockRanges, blockRange)
}

func (r *Result) GetRanges() [][]*big.Int {
	r.mu.Lock()
	defer r.mu.Unlock()
	rst := make([][]*big.Int, len(r.blockRanges))
	copy(rst, r.blockRanges)
	r.blockRanges = [][]*big.Int{}

	return rst
}

// TransferDownloader downloads transfers from single block using number.
type TransferDownloader interface {
	GetTransfersByNumber(context.Context, *big.Int) ([]Transfer, error)
}

func checkRanges(parent context.Context, client BalanceReader, cache *balanceCache, downloader TransferDownloader, account common.Address, ranges [][]*big.Int) ([][]*big.Int, []*big.Int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	c := NewConcurrentDownloader(ctx)

	for _, blocksRange := range ranges {
		from := blocksRange[0]
		to := blocksRange[1]

		c.Add(func(ctx context.Context) error {
			if from.Cmp(to) >= 0 {
				return nil
			}
			log.Debug("eth transfers comparing blocks", "from", from, "to", to)
			lb, err := cache.BalanceAt(client, ctx, account, from)
			if err != nil {
				return err
			}
			hb, err := cache.BalanceAt(client, ctx, account, to)
			if err != nil {
				return err
			}
			if lb.Cmp(hb) == 0 {
				log.Debug("balances are equal", "from", from, "to", to)
				// In case if balances are equal but non zero we want to check if
				// eth_getTransactionCount return different values, because there
				// still might be transactions
				if lb.Cmp(zero) != 0 {
					return nil
				}

				ln, err := client.NonceAt(ctx, account, from)
				if err != nil {
					return err
				}
				hn, err := client.NonceAt(ctx, account, to)
				if err != nil {
					return err
				}
				if ln == hn {
					log.Debug("transaction count is also equal", "from", from, "to", to)
					return nil
				}
			}
			if new(big.Int).Sub(to, from).Cmp(one) == 0 {
				c.PushBlock(to)
				return nil
			}
			mid := new(big.Int).Add(from, to)
			mid = mid.Div(mid, two)
			cache.BalanceAt(client, ctx, account, mid)
			log.Debug("balances are not equal", "from", from, "mid", mid, "to", to)

			c.PushRange([]*big.Int{from, mid})
			c.PushRange([]*big.Int{mid, to})
			return nil
		})

	}

	select {
	case <-c.WaitAsync():
	case <-ctx.Done():
		log.Error("eth downloader is stuck")
		return nil, nil, errors.New("eth downloader is stuck")
	}

	if c.Error() != nil {
		log.Error("failed to dowload transfers using concurrent downloader", "error", c.Error())
		return nil, nil, c.Error()
	}

	return c.GetRanges(), c.GetBlocks(), nil
}

func findBlocksWithEthTransfers(parent context.Context, client BalanceReader, cache *balanceCache, downloader TransferDownloader, account common.Address, low, high *big.Int) (from *big.Int, blocks []*big.Int, err error) {
	ranges := [][]*big.Int{{low, high}}
	minBlock := big.NewInt(low.Int64())
	blocks = []*big.Int{}
	var lvl = 1
	for len(ranges) > 0 && lvl <= 30 {
		log.Info("check blocks ranges", "lvl", lvl, "ranges len", len(ranges))
		lvl = lvl + 1
		newRanges, newBlocks, err := checkRanges(parent, client, cache, downloader, account, ranges)
		blocks = append(blocks, newBlocks...)
		if err != nil {
			return nil, nil, err
		}

		log.Info("found new ranges", "account", account, "lvl", lvl, "new ranges len", len(newRanges))
		if len(newRanges) > 60 {
			sort.SliceStable(newRanges, func(i, j int) bool {
				return newRanges[i][0].Cmp(newRanges[j][0]) == 1
			})

			newRanges = newRanges[:60]
			minBlock = newRanges[len(newRanges)-1][0]
		}

		ranges = newRanges
	}

	return minBlock, blocks, err
}

func downloadEthConcurrently(c *ConcurrentDownloader, client BalanceReader, cache *balanceCache, downloader TransferDownloader, account common.Address, low, high *big.Int) {
	c.Add(func(ctx context.Context) error {
		if low.Cmp(high) >= 0 {
			return nil
		}
		log.Debug("eth transfers comparing blocks", "low", low, "high", high)
		lb, err := cache.BalanceAt(client, ctx, account, low)
		//lb, err := client.BalanceAt(ctx, account, low)
		if err != nil {
			return err
		}
		hb, err := cache.BalanceAt(client, ctx, account, high)
		//hb, err := client.BalanceAt(ctx, account, high)
		if err != nil {
			return err
		}
		if lb.Cmp(hb) == 0 {
			log.Debug("balances are equal", "low", low, "high", high)
			// In case if balances are equal but non zero we want to check if
			// eth_getTransactionCount return different values, because there
			// still might be transactions
			if lb.Cmp(zero) != 0 {
				return nil
			}

			ln, err := client.NonceAt(ctx, account, low)
			if err != nil {
				return err
			}
			hn, err := client.NonceAt(ctx, account, high)
			if err != nil {
				return err
			}
			if ln == hn {
				log.Debug("transaction count is also equal", "low", low, "high", high)
				return nil
			}
		}
		if new(big.Int).Sub(high, low).Cmp(one) == 0 {
			c.PushBlock(high)
			/*transfers, err := downloader.GetTransfersByNumber(ctx, high)
			if err != nil {
				return err
			}
			c.Push(transfers...)*/
			return nil
		}
		mid := new(big.Int).Add(low, high)
		mid = mid.Div(mid, two)
		cache.BalanceAt(client, ctx, account, mid)
		log.Debug("balances are not equal. spawn two concurrent downloaders", "low", low, "mid", mid, "high", high)
		downloadEthConcurrently(c, client, cache, downloader, account, low, mid)
		downloadEthConcurrently(c, client, cache, downloader, account, mid, high)
		return nil
	})
}
