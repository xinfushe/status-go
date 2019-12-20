package wallet

import (
	"context"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type balanceCache struct {
	// cache maps an address to a map of a block number and the balance of this particular address
	cache          map[common.Address]map[*big.Int]*big.Int
	requestCounter map[common.Address]uint
	cacheCounter   map[common.Address]uint
	lock           sync.RWMutex
}

func (b *balanceCache) readCachedBalance(account common.Address, blockNumber *big.Int) *big.Int {
	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.cache[account][blockNumber]
}

func (b *balanceCache) addBalanceToCache(account common.Address, blockNumber *big.Int, balance *big.Int) {
	b.lock.Lock()
	defer b.lock.Unlock()

	_, exists := b.cache[account]
	if !exists {
		b.cache[account] = make(map[*big.Int]*big.Int)
	}
	b.cache[account][blockNumber] = balance
}

func (b *balanceCache) incRequestsNumber(account common.Address) {
	b.lock.Lock()
	defer b.lock.Unlock()

	cnt, ok := b.requestCounter[account]
	if !ok {
		b.requestCounter[account] = 1
	}

	b.requestCounter[account] = cnt + 1
}

func (b *balanceCache) incCacheHitNumber(account common.Address) {
	b.lock.Lock()
	defer b.lock.Unlock()

	cnt, ok := b.cacheCounter[account]
	if !ok {
		b.cacheCounter[account] = 1
	}

	b.cacheCounter[account] = cnt + 1
}

func (b *balanceCache) getStats(account common.Address) (uint, uint) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.requestCounter[account], b.cacheCounter[account]
}

func (b *balanceCache) BalanceAt(client BalanceReader, ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	b.incRequestsNumber(account)
	cachedBalance := b.readCachedBalance(account, blockNumber)
	if cachedBalance != nil {
		b.incCacheHitNumber(account)
		return cachedBalance, nil
	}
	balance, err := client.BalanceAt(ctx, account, blockNumber)
	if err != nil {
		return nil, err
	}
	b.addBalanceToCache(account, blockNumber, balance)

	return balance, nil
}

func newBalanceCache() *balanceCache {
	return &balanceCache{
		cache:          make(map[common.Address]map[*big.Int]*big.Int),
		requestCounter: make(map[common.Address]uint),
		cacheCounter:   make(map[common.Address]uint),
	}
}
