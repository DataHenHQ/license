package license

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

type zeroReader struct{}
type fooStruct struct {
	Foo string `json:"foo"`
}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestVerifyValid(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())

	ok := r.Verify(pub)
	if !ok {
		t.Errorf("should return ok")
	}
}

func TestVerifyExpired(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now().Add(-2*time.Minute))

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func TestVerifyWrongMsg(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	wrongMsg := []byte(`{"foo":"wrong"}`)
	r.Data = wrongMsg

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func TestVerifyEmptySignature(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	r.Signature = []byte{}

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should return ok")
	}
}

func TestUnmarshalValid(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nr := SignedResponse{}
	json.Unmarshal(rj, &nr)

	ok := nr.Verify(pub)
	if !ok {
		t.Errorf("should return ok")
	}
}

func TestUnmarshalDataValid(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nr := SignedResponse{}
	json.Unmarshal(rj, &nr)

	ok := nr.Verify(pub)
	if !ok {
		t.Errorf("should return ok")
	}

	fs := fooStruct{}
	json.Unmarshal(nr.Data, &fs)
	expected := "bar"
	if fs.Foo != expected {
		t.Errorf("should return '%v' instead of '%v'", expected, fs.Foo)
	}
}

func TestUnmarshalExpired(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now().Add(-2*time.Minute))

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nr := SignedResponse{}
	json.Unmarshal(rj, &nr)

	ok := nr.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func TestUnmarshalWrongMsg(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	wrongMsg := []byte(`{"foo":"wrong"}`)
	r.Data = wrongMsg

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nr := SignedResponse{}
	json.Unmarshal(rj, &nr)

	ok := nr.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func createSignedResponse(msg []byte, tm time.Time) (public ed25519.PublicKey, r SignedResponse) {
	// Generate the key pair
	var zero zeroReader
	public, private, _ := ed25519.GenerateKey(zero)

	// instantiate the signed response
	r = SignedResponse{
		Data:      msg,
		CreatedAt: tm,
	}

	// sign the response
	r.Sign(private)

	return public, r
}
