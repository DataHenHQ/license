package license

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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

func TestSignedResponseVerifyValid(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())

	ok := r.Verify(pub)
	if !ok {
		t.Errorf("should return ok")
	}
}

func TestSignedResponseVerifyExpired(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now().Add(-2*time.Minute))

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func TestSignedResponseVerifyWrongMsg(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	wrongMsg := []byte(`{"foo":"wrong"}`)
	r.Data = wrongMsg

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should not return ok")
	}
}

func TestSignedResponseVerifyEmptySignature(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	r.Signature = []byte{}

	ok := r.Verify(pub)
	if ok {
		t.Errorf("should return ok")
	}
}

func TestSignedResponseUnmarshalValid(t *testing.T) {
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

func TestSignedResponseUnmarshalDataValid(t *testing.T) {
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

func TestSignedResponseUnmarshalExpired(t *testing.T) {
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

func TestSignedResponseUnmarshalWrongMsg(t *testing.T) {
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

func TestSignSuccess(t *testing.T) {
	// Generate the key pair
	var zero zeroReader
	_, private, _ := ed25519.GenerateKey(zero)

	// assign to the global variable
	PrivateKey = private

	// create the data struct
	data := struct {
		Foo string `json:"foo"`
	}{Foo: "bar"}

	msg := []byte(`{"foo":"bar"}`)

	// sign the data
	r, err := Sign(data)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nr := SignedResponse{}

	// unmarshal the json
	json.Unmarshal(rj, &nr)
	fmt.Println(nr.CreatedAt)

	if string(nr.Data) != string(msg) {
		t.Errorf("should return %v, instead of: %v", string(msg), string(rj))
	}
}

func TestSignFailOnUnsupportedType(t *testing.T) {
	// Generate the key pair
	var zero zeroReader
	_, private, _ := ed25519.GenerateKey(zero)

	// assign to the global variable
	PrivateKey = private

	// create the data struct
	data := make(chan int)

	// sign the data
	_, err := Sign(data)
	if err == nil {
		t.Errorf("should return error, instead of: %v", err)
	}

}

func TestVerifySuccess(t *testing.T) {
	// Generate the key pair
	var zero zeroReader
	public, private, _ := ed25519.GenerateKey(zero)

	// assign to the global variables
	PrivateKey = private
	PublicKey = public

	// create the data struct
	type Data struct {
		Foo string `json:"foo"`
	}
	data := Data{Foo: "bar"}

	msg := []byte(`{"foo":"bar"}`)

	// sign the data
	r, err := Sign(data)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	nmsg, err := Verify(rj)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	if string(nmsg) != string(msg) {
		t.Errorf("should return %v, instead of: %v", string(msg), string(rj))
	}

	// verify the new data is correct
	ndata := Data{}
	json.Unmarshal(nmsg, &ndata)

	if ndata.Foo != "bar" {
		t.Errorf("should return 'bar' instead of %v", ndata.Foo)
	}

}

func TestVerifyFail(t *testing.T) {
	// Generate the key pair
	var zero zeroReader
	public, private, _ := ed25519.GenerateKey(zero)

	// assign to the global variables
	PrivateKey = private
	PublicKey = public

	msg := []byte(`{"failhere`)

	nd, err := Verify(msg)
	if err == nil {
		t.Errorf("should return error, instead of: %v", err)
	}

	if len(nd) > 0 {
		t.Errorf("should not return something, instead of: %v", nd)
	}

}

func TestVerifyWrongMsg(t *testing.T) {
	msg := []byte(`{"foo":"bar"}`)
	pub, r := createSignedResponse(msg, time.Now())
	// assigning global variable
	PublicKey = pub

	wrongMsg := []byte(`{"foo":"wrong"}`)
	r.Data = wrongMsg

	rj, err := json.Marshal(r)
	if err != nil {
		t.Errorf("should not return error, instead of: %v", err)
	}

	_, err = Verify(rj)
	if err == nil {
		t.Errorf("should return error, instead of %v", err)
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
