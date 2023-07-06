/*
Copyright 2023 Keylime Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"github.com/keylime/attestation-operator/pkg/client/common"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AgentSpec defines the desired state of Agent
type AgentSpec struct {
	// Verifier is the verifier that the agent should be added to. The expected format is "IP:port" or "Host:port".
	Verifier string `json:"foo,omitempty"`
}

// AgentStatus defines the observed state of Agent
type AgentStatus struct {
	// State represents the state of the agent from the view of the controller
	State AgentState `json:"state"`

	// Registrar reflects the status of the agent in the registrar
	Registrar *RegistrarStatus `json:"registrar,omitempty"`

	// Verifier reflects the status of the agent in the verifier.
	// NOTE: this will only be populated if the agent has been added to a verifier.
	Verifier *VerifierStatus `json:"verifier,omitempty"`
}

// AgentState is an overall state of the agent from the view of the controller
type AgentState string

const (
	// AgentUnknown means that the state of the agent is currently unknown
	AgentUnknown AgentState = "Unknown"

	// AgentRegistered means that the agent is registered with the registrar but is not added to a verifier yet
	AgentRegistered AgentState = "Registered"

	// AgentVerifying means that the agent is added to a verifier and is in the GetQuote loop
	AgentVerifying AgentState = "Verifying"
)

// RegistrarStatus reflects the status of an agent in the registrar
type RegistrarStatus struct {
	// AIK is base64 encoded. The AIK format is TPM2B_PUBLIC from tpm2-tss.
	// TODO: break this down
	AIK []byte `json:"aik,omitempty"`
	// EK is the public key of the endorsement key
	EK []byte `json:"ek,omitempty"`
	// EKCert is the DER encoded certificate for the endorsment key
	EKCert []byte `json:"ekCertificate,omitempty"`
	// AgentCert is the DER encoded server certificate of the agent
	AgentCert []byte `json:"agentCertificate,omitempty"`
	// AgentIP is the IP of where to reach the agent
	AgentIP string `json:"agentIP,omitempty"`
	// AgentPort is the port number of where the agent is listening on
	AgentPort uint16 `json:"agentPort,omitempty"`
	// RegCount is the registration counter
	RegCount uint `json:"regcount,omitempty"`
}

// VerifierStatus reflects the status of an agent in the verifier
type VerifierStatus struct {
	OperationalState            string                    `json:"operationalState,omitempty"`
	OperationalStateDescription string                    `json:"operationalStateDescription,omitempty"`
	V                           []byte                    `json:"v,omitempty"`
	TPMPolicy                   *verifier.TPMPolicy       `json:"tpmPolicy,omitempty"`
	VTPMPolicy                  *verifier.TPMPolicy       `json:"vtpmPolicy,omitempty"`
	MetaData                    map[string]any            `json:"metadata,omitempty"`
	HasMBRefState               bool                      `json:"hasMBRefState"`
	HasRuntimePolicy            bool                      `json:"hasRuntimePolicy"`
	AcceptTPMHashAlgs           []common.TPMHashAlg       `json:"acceptTPMHashAlgs,omitempty"`
	AcceptTPMEncryptionAlgs     []common.TPMEncryptionAlg `json:"acceptTPMEncAlgs,omitempty"`
	AcceptTPMSigningAlgs        []common.TPMSigningAlg    `json:"acceptTPMSignAlgs,omitempty"`
	HashAlg                     common.TPMHashAlg         `json:"hashAlg,omitempty"`
	EncryptionAlg               common.TPMEncryptionAlg   `json:"encAlg,omitempty"`
	SigningAlg                  common.TPMSigningAlg      `json:"signAlg,omitempty"`
	SeverityLevel               uint16                    `json:"severityLevel,omitempty"`
	LastEventID                 string                    `json:"lastEventID,omitempty"`
	AttestationCount            uint                      `json:"attestationCount,omitempty"`
	LastReceivedQuote           metav1.Time               `json:"lastReceivedQuote,omitempty"`
	LastSuccessfulAttestation   metav1.Time               `json:"lastSuccessfulAttestation"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// Agent is the Schema for the agents API
type Agent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentSpec   `json:"spec,omitempty"`
	Status AgentStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AgentList contains a list of Agent
type AgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Agent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Agent{}, &AgentList{})
}
