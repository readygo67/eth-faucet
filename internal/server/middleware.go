package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kataras/hcaptcha"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni/v3"
)

type Limiter struct {
	mutex      sync.Mutex
	storage    *Storage
	proxyCount int
	ttl        time.Duration
}

func NewLimiter(storage *Storage, proxyCount int, ttl time.Duration) *Limiter {
	return &Limiter{
		storage:    storage,
		proxyCount: proxyCount,
		ttl:        ttl,
	}
}

func (l *Limiter) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	address, err := readAddress(r)
	if err != nil {
		var mr *malformedRequest
		if errors.As(err, &mr) {
			renderJSON(w, claimResponse{Message: mr.message}, mr.status)
		} else {
			renderJSON(w, claimResponse{Message: http.StatusText(http.StatusInternalServerError)}, http.StatusInternalServerError)
		}
		return
	}

	if l.ttl <= 0 {
		next.ServeHTTP(w, r)
		return
	}

	clientIP := getClientIPFromRequest(l.proxyCount, r)
	l.mutex.Lock()
	limited, _, err := l.limitByKey(w, address)
	if err != nil {
		l.mutex.Unlock()
		log.WithError(err).Error("Failed to check rate limit for address")
		renderJSON(w, claimResponse{Message: "Internal server error"}, http.StatusInternalServerError)
		return
	}
	if limited {
		l.mutex.Unlock()
		return
	}

	limited, _, err = l.limitByKey(w, clientIP)
	if err != nil {
		l.mutex.Unlock()
		log.WithError(err).Error("Failed to check rate limit for IP")
		renderJSON(w, claimResponse{Message: "Internal server error"}, http.StatusInternalServerError)
		return
	}
	if limited {
		l.mutex.Unlock()
		return
	}
	l.mutex.Unlock()

	next.ServeHTTP(w, r)
	status := w.(negroni.ResponseWriter).Status()
	if status == http.StatusOK || status == http.StatusPartialContent {
		// Request succeeded, record the time
		now := time.Now()
		if err := l.storage.SetLastRequestTime(address, now); err != nil {
			log.WithError(err).Error("Failed to store address request time")
		}
		if err := l.storage.SetLastRequestTime(clientIP, now); err != nil {
			log.WithError(err).Error("Failed to store IP request time")
		}
		log.WithFields(log.Fields{
			"address":  address,
			"clientIP": clientIP,
		}).Info("Request succeeded, rate limit applied")
	}
}

func (l *Limiter) limitByKey(w http.ResponseWriter, key string) (bool, time.Duration, error) {
	limited, remaining, err := l.storage.IsWithinLimit(key, l.ttl)
	if err != nil {
		return false, 0, err
	}
	if limited {
		errMsg := fmt.Sprintf("You have exceeded the rate limit. Please wait %s before you try again", remaining.Round(time.Second))
		renderJSON(w, claimResponse{Message: errMsg}, http.StatusTooManyRequests)
		return true, remaining, nil
	}
	return false, 0, nil
}

func getClientIPFromRequest(proxyCount int, r *http.Request) string {
	var ip string
	
	if proxyCount > 0 {
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			xForwardedForParts := strings.Split(xForwardedFor, ",")
			// Avoid reading the user's forged request header by configuring the count of reverse proxies
			partIndex := len(xForwardedForParts) - proxyCount
			if partIndex < 0 {
				partIndex = 0
			}
			ip = strings.TrimSpace(xForwardedForParts[partIndex])
		}
	}

	if ip == "" {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
	}

	// Normalize loopback addresses: convert IPv6 ::1 to IPv4 127.0.0.1 for consistency
	if ip == "::1" {
		ip = "127.0.0.1"
	}
	
	return ip
}

type Captcha struct {
	client *hcaptcha.Client
}

func NewCaptcha(hcaptchaSiteKey, hcaptchaSecret string) *Captcha {
	client := hcaptcha.New(hcaptchaSecret)
	client.SiteKey = hcaptchaSiteKey
	return &Captcha{client: client}
}

func (c *Captcha) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	response := c.client.VerifyToken(r.Header.Get("h-captcha-response"))
	if !response.Success {
		renderJSON(w, claimResponse{Message: "Captcha verification failed, please try again"}, http.StatusTooManyRequests)
		return
	}

	next.ServeHTTP(w, r)
}
