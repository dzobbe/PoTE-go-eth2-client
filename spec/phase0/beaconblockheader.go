// Copyright © 2020 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package phase0

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
)

const (
	// LegacyBeaconBlockHeaderSize is the SSZ size of a beacon block header prior to the TEE extensions.
	LegacyBeaconBlockHeaderSize = 112
	// ProposerTEEQuoteLength is the fixed size of the proposer TEE attestation.
	ProposerTEEQuoteLength = 8192
)

// BeaconBlockHeader represents the header of a beacon block without its content.
type BeaconBlockHeader struct {
	Slot             Slot
	ProposerIndex    ValidatorIndex
	ParentRoot       Root `ssz-size:"32"`
	StateRoot        Root `ssz-size:"32"`
	BodyRoot         Root `ssz-size:"32"`
	ProposerTEEType  uint8
	ProposerTEEQuote [ProposerTEEQuoteLength]byte `ssz-size:"8192"`
}

// beaconBlockHeaderJSON is a raw representation of the struct.
type beaconBlockHeaderJSON struct {
	Slot             string `json:"slot"`
	ProposerIndex    string `json:"proposer_index"`
	ParentRoot       string `json:"parent_root"`
	StateRoot        string `json:"state_root"`
	BodyRoot         string `json:"body_root"`
	ProposerTEEType  *uint8 `json:"proposer_tee_type,omitempty"`
	ProposerTEEQuote string `json:"proposer_tee_quote,omitempty"`
}

// beaconBlockHeaderYAML is a raw representation of the struct.
type beaconBlockHeaderYAML struct {
	Slot             uint64 `yaml:"slot"`
	ProposerIndex    uint64 `yaml:"proposer_index"`
	ParentRoot       string `yaml:"parent_root"`
	StateRoot        string `yaml:"state_root"`
	BodyRoot         string `yaml:"body_root"`
	ProposerTEEType  *uint8 `yaml:"proposer_tee_type,omitempty"`
	ProposerTEEQuote string `yaml:"proposer_tee_quote,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (b *BeaconBlockHeader) MarshalJSON() ([]byte, error) {
	beaconBlockHeaderJSON := &beaconBlockHeaderJSON{
		Slot:          fmt.Sprintf("%d", b.Slot),
		ProposerIndex: fmt.Sprintf("%d", b.ProposerIndex),
		ParentRoot:    fmt.Sprintf("%#x", b.ParentRoot),
		StateRoot:     fmt.Sprintf("%#x", b.StateRoot),
		BodyRoot:      fmt.Sprintf("%#x", b.BodyRoot),
	}

	if b.ProposerTEEType != 0 || !isZeroTEEQuote(b.ProposerTEEQuote) {
		teeType := b.ProposerTEEType
		beaconBlockHeaderJSON.ProposerTEEType = &teeType
		beaconBlockHeaderJSON.ProposerTEEQuote = fmt.Sprintf("%#x", b.ProposerTEEQuote[:])
	}

	return json.Marshal(beaconBlockHeaderJSON)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BeaconBlockHeader) UnmarshalJSON(input []byte) error {
	// First unmarshal into a raw map to handle proposer_tee_quote as either string or array
	var raw map[string]interface{}
	if err := json.Unmarshal(input, &raw); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	// Convert proposer_tee_type from string to number if needed
	if typeVal, exists := raw["proposer_tee_type"]; exists && typeVal != nil {
		switch v := typeVal.(type) {
		case string:
			// Try to parse as number first
			if num, err := strconv.ParseUint(v, 10, 8); err == nil {
				raw["proposer_tee_type"] = uint8(num)
			} else {
				// Map TEE vendor names to numeric codes
				teeTypeCode := mapTEEVendorNameToCode(v)
				raw["proposer_tee_type"] = uint8(teeTypeCode)
			}
		case float64:
			// Already a number, keep as number
			raw["proposer_tee_type"] = uint8(v)
		case int:
			raw["proposer_tee_type"] = uint8(v)
		case int64:
			raw["proposer_tee_type"] = uint8(v)
		}
	}

	// Convert proposer_tee_quote from array to hex string if needed
	if quoteVal, exists := raw["proposer_tee_quote"]; exists && quoteVal != nil {
		switch v := quoteVal.(type) {
		case []interface{}:
			// Convert byte array to hex string
			bytes := make([]byte, 0, len(v))
			for _, item := range v {
				var bVal byte
				switch num := item.(type) {
				case float64:
					bVal = byte(num)
				case int:
					bVal = byte(num)
				case int64:
					bVal = byte(num)
				default:
					return errors.New("invalid byte value in proposer_tee_quote array")
				}
				bytes = append(bytes, bVal)
			}
			raw["proposer_tee_quote"] = fmt.Sprintf("0x%x", bytes)
		case string:
			// Already a string, keep as is
		default:
			return errors.New("proposer_tee_quote must be either a string or an array")
		}
	}

	// Now unmarshal into the struct
	var beaconBlockHeaderJSON beaconBlockHeaderJSON
	modifiedInput, err := json.Marshal(raw)
	if err != nil {
		return errors.Wrap(err, "failed to re-marshal JSON")
	}
	if err := json.Unmarshal(modifiedInput, &beaconBlockHeaderJSON); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return b.unpack(&beaconBlockHeaderJSON)
}

func (b *BeaconBlockHeader) unpack(beaconBlockHeaderJSON *beaconBlockHeaderJSON) error {
	if beaconBlockHeaderJSON.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(beaconBlockHeaderJSON.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}
	b.Slot = Slot(slot)
	if beaconBlockHeaderJSON.ProposerIndex == "" {
		return errors.New("proposer index missing")
	}
	proposerIndex, err := strconv.ParseUint(beaconBlockHeaderJSON.ProposerIndex, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for proposer index")
	}
	b.ProposerIndex = ValidatorIndex(proposerIndex)
	if beaconBlockHeaderJSON.ParentRoot == "" {
		return errors.New("parent root missing")
	}
	parentRoot, err := hex.DecodeString(strings.TrimPrefix(beaconBlockHeaderJSON.ParentRoot, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for parent root")
	}
	if len(parentRoot) != RootLength {
		return errors.New("incorrect length for parent root")
	}
	copy(b.ParentRoot[:], parentRoot)
	if beaconBlockHeaderJSON.StateRoot == "" {
		return errors.New("state root missing")
	}
	stateRoot, err := hex.DecodeString(strings.TrimPrefix(beaconBlockHeaderJSON.StateRoot, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for state root")
	}
	if len(stateRoot) != RootLength {
		return errors.New("incorrect length for state root")
	}
	copy(b.StateRoot[:], stateRoot)
	if beaconBlockHeaderJSON.BodyRoot == "" {
		return errors.New("body root missing")
	}
	bodyRoot, err := hex.DecodeString(strings.TrimPrefix(beaconBlockHeaderJSON.BodyRoot, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for body root")
	}
	if len(bodyRoot) != RootLength {
		return errors.New("incorrect length for body root")
	}
	copy(b.BodyRoot[:], bodyRoot)

	if beaconBlockHeaderJSON.ProposerTEEType != nil {
		b.ProposerTEEType = *beaconBlockHeaderJSON.ProposerTEEType
	} else {
		b.ProposerTEEType = 0
	}

	if beaconBlockHeaderJSON.ProposerTEEQuote != "" {
		proposerTEEQuote, err := hex.DecodeString(strings.TrimPrefix(beaconBlockHeaderJSON.ProposerTEEQuote, "0x"))
		if err != nil {
			return errors.Wrap(err, "invalid value for proposer tee quote")
		}
		if len(proposerTEEQuote) != ProposerTEEQuoteLength {
			return errors.New("incorrect length for proposer tee quote")
		}
		copy(b.ProposerTEEQuote[:], proposerTEEQuote)
	} else {
		b.ProposerTEEQuote = [ProposerTEEQuoteLength]byte{}
	}

	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (b *BeaconBlockHeader) MarshalYAML() ([]byte, error) {
	beaconBlockHeaderYAML := &beaconBlockHeaderYAML{
		Slot:          uint64(b.Slot),
		ProposerIndex: uint64(b.ProposerIndex),
		ParentRoot:    fmt.Sprintf("%#x", b.ParentRoot),
		StateRoot:     fmt.Sprintf("%#x", b.StateRoot),
		BodyRoot:      fmt.Sprintf("%#x", b.BodyRoot),
	}

	if b.ProposerTEEType != 0 || !isZeroTEEQuote(b.ProposerTEEQuote) {
		teeType := b.ProposerTEEType
		beaconBlockHeaderYAML.ProposerTEEType = &teeType
		beaconBlockHeaderYAML.ProposerTEEQuote = fmt.Sprintf("%#x", b.ProposerTEEQuote[:])
	}

	yamlBytes, err := yaml.MarshalWithOptions(beaconBlockHeaderYAML, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BeaconBlockHeader) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var beaconBlockHeaderJSON beaconBlockHeaderJSON
	if err := yaml.Unmarshal(input, &beaconBlockHeaderJSON); err != nil {
		return err
	}

	return b.unpack(&beaconBlockHeaderJSON)
}

// String returns a string representation of the struct.
func (b *BeaconBlockHeader) String() string {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}

func isZeroTEEQuote(quote [ProposerTEEQuoteLength]byte) bool {
	for _, b := range quote {
		if b != 0 {
			return false
		}
	}

	return true
}

// mapTEEVendorNameToCode maps TEE vendor names to numeric codes.
// TEE vendor types:
// 0 = AMD SEV (Secure Encrypted Virtualization)
// 1 = Intel TDX (Trust Domain Extensions)
// 2 = ARM CCA (Confidential Compute Architecture)
func mapTEEVendorNameToCode(name string) uint8 {
	switch strings.ToUpper(name) {
	case "SEV", "AMD-SEV":
		return 0
	case "TDX", "INTEL-TDX":
		return 1
	case "CCA", "ARM-CCA":
		return 2
	default:
		return 0
	}
}
