package cmd

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"github.com/chainflag/eth-faucet/internal/chain"
	"github.com/chainflag/eth-faucet/internal/server"
)

var (
	appVersion = "v1.2.1"
	chainIDMap = map[string]int{"sepolia": 11155111, "holesky": 17000}

	httpPortFlag = flag.Int("httpport", 8080, "Listener port to serve HTTP connection")
	proxyCntFlag = flag.Int("proxycount", 0, "Count of reverse proxies in front of the server")
	versionFlag  = flag.Bool("version", false, "Print version number")

	payoutFlag   = flag.Float64("faucet.amount", 0.01, "Number of Ethers to transfer per user request")
	intervalFlag = flag.Int("faucet.minutes", 1440, "Number of minutes to wait between funding rounds")
	netnameFlag  = flag.String("faucet.name", "testnet", "Network name to display on the frontend")
	symbolFlag   = flag.String("faucet.symbol", "ETH", "Token symbol to display on the frontend")

	keyJSONFlag  = flag.String("wallet.keyjson", os.Getenv("KEYSTORE"), "Keystore file to fund user requests with")
	keyPassFlag  = flag.String("wallet.keypass", "password.txt", "Passphrase text file to decrypt keystore")
	privKeyFlag  = flag.String("wallet.privkey", os.Getenv("PRIVATE_KEY"), "Private key hex to fund user requests with")
	providerFlag = flag.String("wallet.provider", os.Getenv("WEB3_PROVIDER"), "Endpoint for Ethereum JSON-RPC connection")

	hcaptchaSiteKeyFlag = flag.String("hcaptcha.sitekey", os.Getenv("HCAPTCHA_SITEKEY"), "hCaptcha sitekey")
	hcaptchaSecretFlag  = flag.String("hcaptcha.secret", os.Getenv("HCAPTCHA_SECRET"), "hCaptcha secret")

	erc20TokenAddressFlag = flag.String("erc20.token", os.Getenv("ERC20_TOKEN_ADDRESS"), "ERC20 token contract address (optional)")
	erc20TokenAmountFlag  = flag.Int64("erc20.amount", 100, "Amount of ERC20 tokens to mint per request")
)

func init() {
	// Load .env file BEFORE flag parsing so environment variables are available
	// This must be in cmd package init() because cmd.init() runs before main.init()
	if err := godotenv.Load(); err != nil {
		// .env file is optional, so we only log if there's an error other than file not found
		if _, ok := err.(*os.PathError); !ok {
			log.Printf("Warning: Error loading .env file: %v", err)
		}
	}
	
	// Update flag defaults from environment variables after loading .env
	// Flag defaults are evaluated when flag.String() is called, before .env is loaded
	if envPrivKey := os.Getenv("PRIVATE_KEY"); envPrivKey != "" && *privKeyFlag == "" {
		*privKeyFlag = envPrivKey
	}
	if envProvider := os.Getenv("WEB3_PROVIDER"); envProvider != "" && *providerFlag == "" {
		*providerFlag = envProvider
	}
	if envKeystore := os.Getenv("KEYSTORE"); envKeystore != "" && *keyJSONFlag == "" {
		*keyJSONFlag = envKeystore
	}
	if envHcaptchaSiteKey := os.Getenv("HCAPTCHA_SITEKEY"); envHcaptchaSiteKey != "" && *hcaptchaSiteKeyFlag == "" {
		*hcaptchaSiteKeyFlag = envHcaptchaSiteKey
	}
	if envHcaptchaSecret := os.Getenv("HCAPTCHA_SECRET"); envHcaptchaSecret != "" && *hcaptchaSecretFlag == "" {
		*hcaptchaSecretFlag = envHcaptchaSecret
	}
	if envErc20Token := os.Getenv("ERC20_TOKEN_ADDRESS"); envErc20Token != "" && *erc20TokenAddressFlag == "" {
		*erc20TokenAddressFlag = envErc20Token
	}
	
	flag.Parse()
	if *versionFlag {
		fmt.Println(appVersion)
		os.Exit(0)
	}
}

func Execute() {
	privateKey, err := getPrivateKeyFromFlags()
	if err != nil {
		panic(fmt.Errorf("failed to read private key: %w", err))
	}
	var chainID *big.Int
	if value, ok := chainIDMap[strings.ToLower(*netnameFlag)]; ok {
		chainID = big.NewInt(int64(value))
	}

	txBuilder, err := chain.NewTxBuilder(*providerFlag, privateKey, chainID)
	if err != nil {
		panic(fmt.Errorf("cannot connect to web3 provider: %w", err))
	}

	var erc20Minter *chain.ERC20Minter
	if *erc20TokenAddressFlag != "" {
		erc20Minter, err = chain.NewERC20Minter(*providerFlag, privateKey, *erc20TokenAddressFlag, chainID)
		if err != nil {
			panic(fmt.Errorf("failed to initialize ERC20 minter: %w", err))
		}
		log.WithField("token", *erc20TokenAddressFlag).Info("ERC20 minter initialized")
	}

	config := server.NewConfig(*netnameFlag, *symbolFlag, *httpPortFlag, *intervalFlag, *proxyCntFlag, *payoutFlag, *hcaptchaSiteKeyFlag, *hcaptchaSecretFlag, *erc20TokenAddressFlag, *erc20TokenAmountFlag)
	srv := server.NewServer(txBuilder, erc20Minter, config)

	// Run server in goroutine
	go srv.Run()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// Graceful shutdown
	log.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Server forced to shutdown")
	} else {
		log.Info("Server exited")
	}
}

func getPrivateKeyFromFlags() (*ecdsa.PrivateKey, error) {
	if *privKeyFlag != "" {
		hexkey := strings.TrimSpace(*privKeyFlag)
		// Remove quotes if present (godotenv may preserve quotes from .env file)
		hexkey = strings.Trim(hexkey, `"'`)
		if chain.Has0xPrefix(hexkey) {
			hexkey = hexkey[2:]
		}
		return crypto.HexToECDSA(hexkey)
	} else if *keyJSONFlag == "" {
		return nil, errors.New("missing private key or keystore")
	}

	keyfile, err := chain.ResolveKeyfilePath(*keyJSONFlag)
	if err != nil {
		return nil, err
	}
	password, err := os.ReadFile(*keyPassFlag)
	if err != nil {
		return nil, err
	}

	return chain.DecryptKeyfile(keyfile, strings.TrimRight(string(password), "\r\n"))
}
