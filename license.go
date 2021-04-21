package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// PrivateKey is the global var for setting the private key
var PrivateKey ed25519.PrivateKey

// PublicKey is the global var for setting the public key
var PublicKey ed25519.PublicKey

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
func (r *SignedResponse) Sign(priv ed25519.PrivateKey) {
	// defaults to  time.now
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}

	d := r.TimestampedData()
	sig := ed25519.Sign(priv, d)

	r.Signature = sig

}

// TimestampedData combines data and timestamp
func (r SignedResponse) TimestampedData() (d []byte) {

	d = r.Data

	// appends the created at to the end of the data
	t := []byte(strconv.FormatInt(r.CreatedAt.UnixNano(), 10))
	d = append(d, t...)

	return d
}

// Sign creates the signed response using the global private key variable
func Sign(data interface{}) (sr *SignedResponse, err error) {
	// create the signed response
	r := SignedResponse{}
	rd, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	r.Data = rd

	// sign it
	r.Sign(PrivateKey)

	return &r, nil
}

// Verify verifies the signed response using the global public key variable
func Verify(msg []byte) (data []byte, err error) {
	// unmarshal the signed response
	r := SignedResponse{}
	err = json.Unmarshal(msg, &r)
	if err != nil {
		return nil, err
	}

	// verify it
	ok := r.Verify(PublicKey)
	if !ok {
		return nil, errors.New("verification failed")
	}

	return r.Data, nil
}
