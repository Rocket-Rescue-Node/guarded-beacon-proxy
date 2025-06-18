package ssz

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/Rocket-Rescue-Node/guarded-beacon-proxy/jsontypes"
)

type ValidatorRegistration struct {
	FeeRecipient []byte `ssz-size:"20"`
	GasLimit     uint64
	Timestamp    uint64
	Pubkey       []byte `ssz-size:"48"`
}

type SignedValidatorRegistration struct {
	Message   ValidatorRegistration
	Signature []byte `ssz-size:"96"`
}

type RegisterValidatorRequest []SignedValidatorRegistration

func ToRegisterValidatorRequest(dst *jsontypes.RegisterValidatorRequest, reader io.Reader, maxBytes int64) (error, int) {

	// Get the expected size of the SSZ objects
	size := int64((&SignedValidatorRegistration{}).SizeSSZ())

	totalBytes := int64(0)

	// Read `size` bytes at a time, and ensure the buffer is a multiple of `size`
	buf := bytes.NewBuffer(make([]byte, 0, size))
	for {
		if maxBytes > 0 && totalBytes+size > maxBytes {
			return fmt.Errorf("request body too large"), http.StatusRequestEntityTooLarge
		}
		w, err := io.CopyN(buf, reader, size)
		totalBytes += w
		fmt.Println("w", w)
		if err == io.EOF {
			if w != 0 {
				return fmt.Errorf("buffer is not a positive multiple of SignedValidatorRegistration length: %d", size),
					http.StatusBadRequest
			}
			break
		}
		if err != nil {
			return err, http.StatusInternalServerError
		}
		var signedValidatorRegistration SignedValidatorRegistration
		if err := signedValidatorRegistration.UnmarshalSSZ(buf.Bytes()); err != nil {
			return err, http.StatusBadRequest
		}
		*dst = append(*dst, jsontypes.SignedValidatorRegistration{
			Message: jsontypes.RegisterValidatorMessage{
				FeeRecipient: "0x" + hex.EncodeToString(signedValidatorRegistration.Message.FeeRecipient),
				GasLimit:     strconv.FormatUint(signedValidatorRegistration.Message.GasLimit, 10),
				Timestamp:    strconv.FormatUint(signedValidatorRegistration.Message.Timestamp, 10),
				Pubkey:       "0x" + hex.EncodeToString(signedValidatorRegistration.Message.Pubkey),
			},
			Signature: "0x" + hex.EncodeToString(signedValidatorRegistration.Signature),
		})
		buf.Reset()
	}

	return nil, http.StatusOK
}
