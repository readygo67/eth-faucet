package chain

import (
	"context"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

// NonceProvider interface for getting pending nonce
type NonceProvider interface {
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

// NonceManager manages nonce for a single Ethereum account in a thread-safe manner
type NonceManager struct {
	client      NonceProvider
	address     common.Address
	nonce       uint64
	initialized uint32 // atomic flag to track initialization
}

// NewNonceManager creates a new nonce manager for the given address
func NewNonceManager(client NonceProvider, address common.Address) *NonceManager {
	nm := &NonceManager{
		client:  client,
		address: address,
	}
	nm.refreshNonce(context.Background())
	return nm
}

// GetAndIncrement atomically gets the current nonce and increments it
func (nm *NonceManager) GetAndIncrement() uint64 {
	// Ensure nonce is initialized
	if atomic.LoadUint32(&nm.initialized) == 0 {
		nm.refreshNonce(context.Background())
	}
	return atomic.AddUint64(&nm.nonce, 1) - 1
}

// RefreshNonce refreshes the nonce from the blockchain
func (nm *NonceManager) RefreshNonce(ctx context.Context) {
	nm.refreshNonce(ctx)
}

func (nm *NonceManager) refreshNonce(ctx context.Context) {
	nonce, err := nm.client.PendingNonceAt(ctx, nm.address)
	if err != nil {
		log.WithFields(log.Fields{
			"address": nm.address,
			"error":   err,
		}).Error("failed to refresh account nonce")
		return
	}

	atomic.StoreUint64(&nm.nonce, nonce)
	atomic.StoreUint32(&nm.initialized, 1)
	log.WithField("nonce", nonce).Info("Nonce refreshed successfully")
}
