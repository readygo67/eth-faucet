package chain

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

// ERC20Minter handles minting ERC20 tokens
type ERC20Minter struct {
	client          *ethclient.Client
	privateKey      *ecdsa.PrivateKey
	signer          types.Signer
	fromAddress     common.Address
	tokenAddress    common.Address
	nonce           uint64
	supportsEIP1559 bool
	abi             abi.ABI
}

// ERC20 Mint ABI - standard mint function signature
const erc20MintABI = `[{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

func NewERC20Minter(provider string, privateKey *ecdsa.PrivateKey, tokenAddress string, chainID *big.Int) (*ERC20Minter, error) {
	client, err := ethclient.Dial(provider)
	if err != nil {
		return nil, err
	}

	if chainID == nil {
		chainID, err = client.ChainID(context.Background())
		if err != nil {
			return nil, err
		}
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20MintABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ERC20 ABI: %w", err)
	}

	if !IsValidAddress(tokenAddress, false) {
		return nil, fmt.Errorf("invalid token address: %s", tokenAddress)
	}

	tokenAddr := common.HexToAddress(tokenAddress)
	supportsEIP1559, err := checkEIP1559Support(client)
	if err != nil {
		return nil, err
	}

	minter := &ERC20Minter{
		client:          client,
		privateKey:      privateKey,
		signer:          types.NewLondonSigner(chainID),
		fromAddress:     crypto.PubkeyToAddress(privateKey.PublicKey),
		tokenAddress:    tokenAddr,
		supportsEIP1559: supportsEIP1559,
		abi:             parsedABI,
	}
	minter.refreshNonce(context.Background())

	return minter, nil
}

// Mint mints ERC20 tokens to the specified address
func (m *ERC20Minter) Mint(ctx context.Context, to string, amount *big.Int) (common.Hash, error) {
	if amount == nil || amount.Sign() <= 0 {
		return common.Hash{}, fmt.Errorf("invalid mint amount: must be positive")
	}

	toAddress := common.HexToAddress(to)

	// Encode the mint function call
	data, err := m.abi.Pack("mint", toAddress, amount)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack mint data: %w", err)
	}

	// Estimate gas limit for contract call
	gasLimit, err := m.client.EstimateGas(ctx, ethereum.CallMsg{
		From: m.fromAddress,
		To:   &m.tokenAddress,
		Data: data,
	})
	if err != nil {
		// If estimation fails, use a default gas limit for ERC20 mint
		gasLimit = 100000
		log.WithError(err).Warn("Failed to estimate gas, using default 100000")
	} else {
		// Add 20% buffer to estimated gas
		gasLimit = gasLimit + (gasLimit * 20 / 100)
	}

	// Refresh nonce before minting to ensure we use the correct nonce
	// This is important when multiple transactions are sent from the same account
	m.refreshNonce(ctx)
	nonce := m.getAndIncrementNonce()

	var unsignedTx *types.Transaction

	if m.supportsEIP1559 {
		unsignedTx, err = m.buildEIP1559Tx(ctx, &m.tokenAddress, big.NewInt(0), gasLimit, nonce, data)
	} else {
		unsignedTx, err = m.buildLegacyTx(ctx, &m.tokenAddress, big.NewInt(0), gasLimit, nonce, data)
	}

	if err != nil {
		return common.Hash{}, err
	}

	signedTx, err := types.SignTx(unsignedTx, m.signer, m.privateKey)
	if err != nil {
		return common.Hash{}, err
	}

	if err = m.client.SendTransaction(ctx, signedTx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "nonce") {
			m.refreshNonce(ctx)
		}
		return common.Hash{}, err
	}

	return signedTx.Hash(), nil
}

func (m *ERC20Minter) buildEIP1559Tx(ctx context.Context, to *common.Address, value *big.Int, gasLimit uint64, nonce uint64, data []byte) (*types.Transaction, error) {
	header, err := m.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}

	gasTipCap, err := m.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}

	gasFeeCap := new(big.Int).Mul(header.BaseFee, big.NewInt(2))
	gasFeeCap = new(big.Int).Add(gasFeeCap, gasTipCap)

	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   m.signer.ChainID(),
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        to,
		Value:     value,
		Data:      data,
	}), nil
}

func (m *ERC20Minter) buildLegacyTx(ctx context.Context, to *common.Address, value *big.Int, gasLimit uint64, nonce uint64, data []byte) (*types.Transaction, error) {
	gasPrice, err := m.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}

	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       to,
		Value:    value,
		Data:     data,
	}), nil
}

func (m *ERC20Minter) getAndIncrementNonce() uint64 {
	return atomic.AddUint64(&m.nonce, 1) - 1
}

func (m *ERC20Minter) refreshNonce(ctx context.Context) {
	nonce, err := m.client.PendingNonceAt(ctx, m.fromAddress)
	if err != nil {
		log.WithFields(log.Fields{
			"address": m.fromAddress,
			"error":   err,
		}).Error("failed to refresh ERC20 minter account nonce")
		return
	}

	atomic.StoreUint64(&m.nonce, nonce)
	log.WithField("nonce", nonce).Info("ERC20 minter nonce refreshed successfully")
}
