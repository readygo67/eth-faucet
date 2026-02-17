package server

type Config struct {
	network           string
	symbol            string
	httpPort          int
	interval          int
	payout            float64
	proxyCount        int
	hcaptchaSiteKey   string
	hcaptchaSecret    string
	erc20TokenAddress string
	erc20TokenAmount  int64
}

func NewConfig(network, symbol string, httpPort, interval, proxyCount int, payout float64, hcaptchaSiteKey, hcaptchaSecret, erc20TokenAddress string, erc20TokenAmount int64) *Config {
	return &Config{
		network:           network,
		symbol:            symbol,
		httpPort:          httpPort,
		interval:          interval,
		payout:            payout,
		proxyCount:        proxyCount,
		hcaptchaSiteKey:   hcaptchaSiteKey,
		hcaptchaSecret:    hcaptchaSecret,
		erc20TokenAddress: erc20TokenAddress,
		erc20TokenAmount:  erc20TokenAmount,
	}
}
