package ssz

import (
	"encoding/hex"
	"fmt"
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

func ToRegisterValidatorRequest(dst *jsontypes.RegisterValidatorRequest, buf []byte) error {

	// Ensure the buffer is a multiple of SignedValidatorRegistration.SizeSSZ()
	size := (&SignedValidatorRegistration{}).SizeSSZ()
	if len(buf)%size != 0 {
		return fmt.Errorf("buffer is not a multiple of SignedValidatorRegistration length: %d", size)
	}

	// Unmarshal the buffer SSZ objects
	for i := 0; i < len(buf); i += size {
		section := buf[i : i+size]
		var signedValidatorRegistration SignedValidatorRegistration
		if err := signedValidatorRegistration.UnmarshalSSZ(section); err != nil {
			return err
		}
		*dst = append(*dst, jsontypes.SignedValidatorRegistration{
			Message: jsontypes.RegisterValidatorMessage{
				FeeRecipient: "0x" + hex.EncodeToString(signedValidatorRegistration.Message.FeeRecipient),
				GasLimit:     strconv.FormatUint(signedValidatorRegistration.Message.GasLimit, 10),
				Timestamp:    strconv.FormatUint(signedValidatorRegistration.Message.Timestamp, 10),
				Pubkey:       "0x" + hex.EncodeToString(signedValidatorRegistration.Message.Pubkey),
			},
			Signature: hex.EncodeToString(signedValidatorRegistration.Signature),
		})
	}

	return nil
}
