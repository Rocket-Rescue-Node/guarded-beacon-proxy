package jsontypes

// PrepareBeaconProposerRequest is the in-memory representation of a
// prepare_beacon_proposer API call, be it gRPC or HTTP.
type PrepareBeaconProposerRequest []struct {
	ValidatorIndex string `json:"validator_index"`
	FeeRecipient   string `json:"fee_recipient"`
}

// RegisterValidatorMessage is the in-memory representation of a
// register_validator API call entry, be it gRPC or HTTP.
type RegisterValidatorMessage struct {
	FeeRecipient string `json:"fee_recipient"`
	GasLimit     string `json:"gas_limit"`
	Timestamp    string `json:"timestamp"`
	Pubkey       string `json:"pubkey"`
}

type SignedValidatorRegistration struct {
	Message   RegisterValidatorMessage `json:"message"`
	Signature string                   `json:"signature"`
}

// RegisterValidatorRequest is the in-memory representation of a
// register_validator API call, be it gRPC or HTTP.
type RegisterValidatorRequest []SignedValidatorRegistration
