package guarded_beacon_proxy

type PrepareBeaconProposerRequest []struct {
	ValidatorIndex string `json:"validator_index"`
	FeeRecipient   string `json:"fee_recipient"`
}

type RegisterValidatorMessage struct {
	FeeRecipient string `json:"fee_recipient"`
	GasLimit     string `json:"gas_limit"`
	Timestamp    string `json:"timestamp"`
	Pubkey       string `json:"pubkey"`
}

type RegisterValidatorRequest []struct {
	Message   RegisterValidatorMessage `json:"message"`
	Signature string                   `json:"signature"`
}
