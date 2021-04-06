package license

import (
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"time"
)

type SignedResponse struct {
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	Signature []byte          `json:"signature"`
}

// Verify verifies the data with the timestamp and public key
func (r SignedResponse) Verify(pub ed25519.PublicKey) (ok bool) {

	// if no signature then not valid
	if len(r.Signature) == 0 {
		return false
	}

	// check to see if timestamp expired or not
	expiry := r.CreatedAt.Add(time.Minute)
	if time.Now().After(expiry) {
		return false
	}

	d := r.TimestampedData()
	return ed25519.Verify(pub, d, r.Signature)
}

// Sign signs the data with timestamp and private key
func (r *SignedResponse) Sign(priv ed25519.PrivateKey) (ok bool) {
	d := r.TimestampedData()
	sig := ed25519.Sign(priv, d)
	r.Signature = sig

	return true
}

// TimestampedData combines data and timestamp
func (r SignedResponse) TimestampedData() (d []byte) {
	d = r.Data

	// appends the created at to the end of the data
	t := []byte(strconv.FormatInt(r.CreatedAt.UnixNano(), 10))
	d = append(d, t...)

	return d
}
