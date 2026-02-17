package server

import (
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	log "github.com/sirupsen/logrus"
)

// Storage manages persistent storage for rate limiting using LevelDB
type Storage struct {
	db   *leveldb.DB
	mu   sync.RWMutex
	path string
}

// NewStorage creates a new storage instance
func NewStorage(dbPath string) (*Storage, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, err
	}

	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}

	storage := &Storage{
		db:   db,
		path: dbPath,
	}

	log.WithField("path", dbPath).Info("LevelDB storage initialized")
	return storage, nil
}

// SetLastRequestTime records the last successful request time for a key (IP or address)
func (s *Storage) SetLastRequestTime(key string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert time to Unix timestamp (int64)
	timestamp := t.Unix()
	
	// Encode timestamp as 8 bytes (big-endian)
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, uint64(timestamp))

	// Use "req:" prefix for request records
	dbKey := []byte("req:" + key)
	
	if err := s.db.Put(dbKey, value, nil); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"key":       key,
		"timestamp": timestamp,
	}).Debug("Stored last request time")
	return nil
}

// GetLastRequestTime retrieves the last successful request time for a key
func (s *Storage) GetLastRequestTime(key string) (time.Time, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dbKey := []byte("req:" + key)
	value, err := s.db.Get(dbKey, nil)
	if err == leveldb.ErrNotFound {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}

	if len(value) != 8 {
		return time.Time{}, false, nil
	}

	// Decode timestamp from 8 bytes (big-endian)
	timestamp := int64(binary.BigEndian.Uint64(value))
	t := time.Unix(timestamp, 0)

	return t, true, nil
}

// IsWithinLimit checks if the key has made a request within the specified duration
func (s *Storage) IsWithinLimit(key string, limitDuration time.Duration) (bool, time.Duration, error) {
	lastTime, exists, err := s.GetLastRequestTime(key)
	if err != nil {
		return false, 0, err
	}

	if !exists {
		return false, 0, nil
	}

	elapsed := time.Since(lastTime)
	if elapsed < limitDuration {
		remaining := limitDuration - elapsed
		return true, remaining, nil
	}

	return false, 0, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Cleanup removes old entries that are beyond the limit duration
// This is optional and can be called periodically to reduce database size
func (s *Storage) Cleanup(limitDuration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	iter := s.db.NewIterator(util.BytesPrefix([]byte("req:")), nil)
	defer iter.Release()

	cutoffTime := time.Now().Add(-limitDuration * 2) // Keep entries for 2x limit duration
	cutoffTimestamp := cutoffTime.Unix()

	var deleted int
	for iter.Next() {
		value := iter.Value()
		if len(value) == 8 {
			timestamp := int64(binary.BigEndian.Uint64(value))
			if timestamp < cutoffTimestamp {
				if err := s.db.Delete(iter.Key(), nil); err != nil {
					log.WithError(err).Warn("Failed to delete old entry")
				} else {
					deleted++
				}
			}
		}
	}

	if deleted > 0 {
		log.WithField("deleted", deleted).Info("Cleaned up old rate limit entries")
	}

	return iter.Error()
}
