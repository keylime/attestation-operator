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
	// VerifierName is the verifier that the agent should be scheduled on. The expected format is "IP:port" or "Host:port".
	VerifierName string `json:"verifierName"`

	// EKCertificateStore contains all the configuration settings for the verification of the EK certificate of the agent.
	EKCertificateStore EKCertificateStore `json:"ekCertificateStore"`

	// SecurePayload contains all the configuration settings for the Secure Payload mechanism of Keylime.
	SecurePayload SecurePayload `json:"securePayload"`
}

// EKCertificateStore contains all the configuration settings for the verification of the EK certificate of the agent.
type EKCertificateStore struct {
	// EnableVerification turns on EK certificate verification. If this is enabled, you must also set either the SecretName below, or the ControllerDirectoryPath.
	EnableVerification bool `json:"enableVerification"`

	// SecretName is the name of a secret which should contain CA certificates that should be used to verify the EK certificate of the agent if EnableVerification is set.
	//
	// If EnableVerification is true, but SecretName is empty, then the controller will fall back to try to use the CA certificates as set with the optional KEYLIME_TPM_CERT_STORE setting.
	// NOTE: It is recommended to use a secret though. However, in cases where people do not feel comfortable to give the service account of the controller access to secrets, or want to bake in
	// the secure payloads into the controller image or mount a volume/secret into the controller for that purpose, this fallback mechanism provides a way to accomodate that.
	SecretName string `json:"secretName"`
}

// SecurePayload contains all the configuration settings for the Secure Payload mechanism of Keylime.
type SecurePayload struct {
	// EnableSecurePayload turns on the Secure Payload delivery of Keylime. It happens during the process when an agent is added to a verifier.
	EnableSecurePayload bool `json:"enableSecurePayload"`

	// SecretName is the name of a secret which contents should be delivered to the agent via the Secure Payload mechanism.
	// NOTE: If there is a change in this value after the agent has been added to a verifier, this will effectively delete the agent from the verifier and add it again!
	//
	// If EnableSecurePayload is true, but SecretName is empty, then the controller will fall back to try to use a directory as set with the optional KEYLIME_SECURE_PAYLOAD_DIR setting.
	// NOTE: It is recommended to use a secret though. However, in cases where people do not feel comfortable to give the service account of the controller access to secrets, or want to bake in
	// the secure payloads into the controller image or mount a volume/secret into the controller for that purpose, this fallback mechanism provides a way to accomodate that.
	SecretName string `json:"secretName"`

	// AgentVerify will additionally request to verify with the agent that after the agent has been added to the verifier that the bootstrap keys were delivered and derived successfully.
	// This means that the secure payload could technically be decrypted by the agent. However, this does not verify unpacking of the payload, just that the correct keys were
	// derived on the agent.
	// NOTE: the verification mechanism fails at times, and is also optional in the keylime_tenant CLI, so we make this switchable here as well.
	AgentVerify bool
}

func (p *SecurePayload) Status() string {
	if !p.EnableSecurePayload {
		return ""
	}
	if p.SecretName != "" {
		return "secret:" + p.SecretName
	}
	return "KEYLIME_SECURE_PAYLOAD_DIR"
}

// AgentStatus defines the observed state of Agent
type AgentStatus struct {
	// Phase represents the phase that the agent is in from the view of the controller
	Phase AgentPhase `json:"phase"`

	// PhaseReason is a brief reason why the agent is in that phase.
	PhaseReason PhaseReason `json:"phaseReason,omitempty"`

	// PhaseMessage is a detailed explanation why the agent is in that phase.
	PhaseMessage string `json:"phaseMessage,omitempty"`

	// Pod of the agent that is running the agent
	Pod string `json:"pod,omitempty"`

	// Node that the pod of the agent is running on and that the agent is attesting
	Node string `json:"node,omitempty"`

	// Registrar reflects the status of the agent in the registrar
	Registrar *RegistrarStatus `json:"registrar,omitempty"`

	// EKCertificateVerified will be set if EK certificate verification is activated for the agent, and will be true if EK certificate verification passes successfully.
	EKCertificateVerified *bool `json:"ekCertificateVerified,omitempty"`

	// EKCertificateAuthority will be set if EK certificate verification is activated and passed successfully and it will be the X500 subject of the certificate authority that signed the EK certificate of the agent.
	EKCertificateAuthority string `json:"ekCertificateAuthority,omitempty"`

	// VerifierName is the verifier that the agent is scheduled on. This will reflect the same value as the `.spec.verifierName` once the controller has achieved that state.
	VerifierName string `json:"verifierName,omitempty"`

	// Verifier reflects the status of the agent in the verifier.
	// NOTE: this will only be populated if the agent has been added to a verifier.
	Verifier *VerifierStatus `json:"verifier,omitempty"`

	// SecurePayloadDelivered denotes the secure payload that was delivered to the agent if any at all.
	SecurePayloadDelivered string `json:"securePayloadDelivered,omitempty"`
}

// AgentPhase is the overall phase that the agent is in from the view of the controller
type AgentPhase string

const (
	// AgentUnknown means that the state of the agent is currently undetermined
	AgentUndetermined AgentPhase = "Undetermined"

	// AgentRegistered means that the agent is registered with the registrar but is not added to a verifier yet
	AgentRegistered AgentPhase = "Registered"

	// AgentEKVerification means that the agent is registered with the registrar and EK verification was requested
	AgentEKVerification AgentPhase = "EKVerification"

	// AgentUnschedulable means that the agent cannot be added to the verifier in the spec because it cannot be found
	AgentUnschedulable AgentPhase = "Unschedulable"

	// AgentVerifying means that the agent is added to a verifier and is in the GetQuote loop
	AgentVerifying AgentPhase = "Verifying"
)

type PhaseReason string

const (
	UnsuccessfulChecks            PhaseReason = "UnsuccessfulChecks"
	RegistrarCheckSuccess         PhaseReason = "RegistrarCheckSuccess"
	EKVerificationProcessingError PhaseReason = "EKVerificationProcessingError"
	EKVerificationFailure         PhaseReason = "EKVerificationFailure"
	EKVerificationSuccess         PhaseReason = "EKVerificationSuccess"
	InvalidVerifier               PhaseReason = "InvalidVerifier"
	AddToVerifierError            PhaseReason = "AddToVerifierError"
	VerifierCheckSuccess          PhaseReason = "VerifierCheckSuccess"
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
