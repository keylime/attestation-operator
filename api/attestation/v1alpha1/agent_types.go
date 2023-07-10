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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AgentSpec defines the desired state of Agent
type AgentSpec struct {
	// Verifier is the verifier that the agent should be scheduled on. The expected format is "IP:port" or "Host:port".
	Verifier string `json:"verifier"`
}

// AgentStatus defines the observed state of Agent
type AgentStatus struct {
	// Phase represents the phase that the agent is in from the view of the controller
	Phase AgentPhase `json:"phase"`

	PhaseReason PhaseReason `json:"phaseReason,omitempty"`

	PhaseMessage string `json:"phaseMessage,omitempty"`

	// Pod of the agent that is running the agent
	Pod string `json:"pod,omitempty"`

	// Node that the pod of the agent is running on and that the agent is attesting
	Node string `json:"node,omitempty"`

	// Registrar reflects the status of the agent in the registrar
	Registrar *RegistrarStatus `json:"registrar,omitempty"`

	// Verifier reflects the status of the agent in the verifier.
	// NOTE: this will only be populated if the agent has been added to a verifier.
	Verifier *VerifierStatus `json:"verifier,omitempty"`
}

// AgentPhase is the overall phase that the agent is in from the view of the controller
type AgentPhase string

const (
	// AgentUnknown means that the state of the agent is currently undetermined
	AgentUndetermined AgentPhase = "Undetermined"

	// AgentRegistered means that the agent is registered with the registrar but is not added to a verifier yet
	AgentRegistered AgentPhase = "Registered"

	// AgentUnschedulable means that the agent cannot be added to the verifier in the spec because it cannot be found
	AgentUnschedulable AgentPhase = "Unschedulable"

	// AgentVerifying means that the agent is added to a verifier and is in the GetQuote loop
	AgentVerifying AgentPhase = "Verifying"
)

type PhaseReason string

const (
	UnsuccessfulChecks    PhaseReason = "UnsuccessfulChecks"
	RegistrarCheckSuccess PhaseReason = "RegistrarCheckSuccess"
	InvalidVerifier       PhaseReason = "InvalidVerifier"
	AddToVerifierError    PhaseReason = "AddToVerifierError"
	VerifierCheckSuccess  PhaseReason = "VerifierCheckSuccess"
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
	OperationalState            string             `json:"operationalState,omitempty"`
	OperationalStateDescription string             `json:"operationalStateDescription,omitempty"`
	V                           []byte             `json:"v,omitempty"`
	TPMPolicy                   *TPMPolicy         `json:"tpmPolicy,omitempty"`
	VTPMPolicy                  *TPMPolicy         `json:"vtpmPolicy,omitempty"`
	MetaData                    string             `json:"metadata,omitempty"`
	HasMBRefState               bool               `json:"hasMBRefState"`
	HasRuntimePolicy            bool               `json:"hasRuntimePolicy"`
	AcceptTPMHashAlgs           []TPMHashAlg       `json:"acceptTPMHashAlgs,omitempty"`
	AcceptTPMEncryptionAlgs     []TPMEncryptionAlg `json:"acceptTPMEncAlgs,omitempty"`
	AcceptTPMSigningAlgs        []TPMSigningAlg    `json:"acceptTPMSignAlgs,omitempty"`
	HashAlg                     TPMHashAlg         `json:"hashAlg,omitempty"`
	EncryptionAlg               TPMEncryptionAlg   `json:"encAlg,omitempty"`
	SigningAlg                  TPMSigningAlg      `json:"signAlg,omitempty"`
	SeverityLevel               uint16             `json:"severityLevel,omitempty"`
	LastEventID                 string             `json:"lastEventID,omitempty"`
	AttestationCount            uint               `json:"attestationCount,omitempty"`
	LastReceivedQuote           metav1.Time        `json:"lastReceivedQuote,omitempty"`
	LastSuccessfulAttestation   metav1.Time        `json:"lastSuccessfulAttestation"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.status.pod`
//+kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.node`
//+kubebuilder:printcolumn:name="Verifier",type=string,JSONPath=`.spec.verifier`
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.verifier.operationalState`
//+kubebuilder:printcolumn:name="Last Successful Attestation",type="date",format="date-time",JSONPath=".status.verifier.lastSuccessfulAttestation"

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