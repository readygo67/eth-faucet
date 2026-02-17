package server

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni/v3"

	"github.com/chainflag/eth-faucet/internal/chain"
	"github.com/chainflag/eth-faucet/web"
)

type Server struct {
	chain.TxBuilder
	erc20Minter *chain.ERC20Minter
	cfg         *Config
	server      *http.Server
	payoutWei   *big.Int
}

func NewServer(builder chain.TxBuilder, erc20Minter *chain.ERC20Minter, cfg *Config) *Server {
	return &Server{
		TxBuilder:   builder,
		erc20Minter: erc20Minter,
		cfg:         cfg,
		payoutWei:   chain.EtherToWei(cfg.payout),
	}
}

func (s *Server) setupRouter() *http.ServeMux {
	router := http.NewServeMux()
	router.Handle("/", http.FileServer(web.Dist()))
	limiter := NewLimiter(s.cfg.proxyCount, time.Duration(s.cfg.interval)*time.Minute)
	middlewares := []negroni.Handler{limiter}
	if s.cfg.hcaptchaSecret != "" {
		middlewares = append(middlewares, NewCaptcha(s.cfg.hcaptchaSiteKey, s.cfg.hcaptchaSecret))
	}
	middlewares = append(middlewares, negroni.Wrap(s.handleClaim()))
	router.Handle("/api/claim", negroni.New(middlewares...))
	router.Handle("/api/info", s.handleInfo())

	return router
}

func (s *Server) Run() {
	n := negroni.New(negroni.NewRecovery(), negroni.NewLogger())
	n.UseHandler(s.setupRouter())

	s.server = &http.Server{
		Addr:         ":" + strconv.Itoa(s.cfg.httpPort),
		Handler:      n,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Infof("Starting http server on port %d", s.cfg.httpPort)
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleClaim() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Address has already been validated by limiter
		address, _ := readAddress(r)

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Send ETH
		ethTxHash, err := s.Transfer(ctx, address, new(big.Int).Set(s.payoutWei))
		if err != nil {
			log.WithFields(log.Fields{
				"error":   err,
				"address": address,
			}).Error("Failed to send ETH transaction")
			renderJSON(w, claimResponse{Message: fmt.Sprintf("ETH transaction failed: %v", err)}, http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"txHash":  ethTxHash,
			"address": address,
			"type":    "ETH",
		}).Info("ETH transaction sent successfully")

		// Mint ERC20 tokens if configured
		var erc20TxHash common.Hash
		if s.erc20Minter != nil {
			// Wait a short time to ensure ETH transaction is submitted to the mempool
			// This helps prevent nonce conflicts
			time.Sleep(200 * time.Millisecond)

			tokenAmount := big.NewInt(s.cfg.erc20TokenAmount)
			erc20TxHash, err = s.erc20Minter.Mint(ctx, address, tokenAmount)
			if err != nil {
				log.WithFields(log.Fields{
					"error":   err,
					"address": address,
				}).Error("Failed to mint ERC20 tokens")
				// ETH was sent successfully, but ERC20 mint failed
				resp := claimResponse{
					Message:   fmt.Sprintf("ETH sent (Txhash: %s), but ERC20 mint failed: %v", ethTxHash, err),
					EthTxHash: ethTxHash.Hex(),
				}
				renderJSON(w, resp, http.StatusPartialContent)
				return
			}

			log.WithFields(log.Fields{
				"txHash":  erc20TxHash,
				"address": address,
				"amount":  tokenAmount,
				"type":    "ERC20",
			}).Info("ERC20 tokens minted successfully")

			resp := claimResponse{
				Message:     fmt.Sprintf("ETH Txhash: %s, ERC20 Txhash: %s", ethTxHash, erc20TxHash),
				EthTxHash:   ethTxHash.Hex(),
				Erc20TxHash: erc20TxHash.Hex(),
			}
			renderJSON(w, resp, http.StatusOK)
		} else {
			resp := claimResponse{
				Message:   fmt.Sprintf("ETH Txhash: %s", ethTxHash),
				EthTxHash: ethTxHash.Hex(),
			}
			renderJSON(w, resp, http.StatusOK)
		}
	}
}

func (s *Server) handleInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		resp := infoResponse{
			Account:         s.Sender().String(),
			Network:         s.cfg.network,
			Symbol:          s.cfg.symbol,
			Payout:          strconv.FormatFloat(s.cfg.payout, 'f', -1, 64),
			HcaptchaSiteKey: s.cfg.hcaptchaSiteKey,
		}
		
		// Add ERC20 token info if configured
		if s.cfg.erc20TokenAddress != "" {
			resp.Erc20TokenAmount = strconv.FormatInt(s.cfg.erc20TokenAmount, 10)
			// Default token symbol to "FAUCET" if not specified
			resp.Erc20TokenSymbol = "FAUCET"
		}
		
		renderJSON(w, resp, http.StatusOK)
	}
}
