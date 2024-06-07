/*
Copyright 2024 Keylime Authors.

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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageInfo defines global information for initial image in initial deployment task
type ImageInfo struct {
	// ImageRepositoryPath is a string to specify where to download images
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Image Repository Path"
	ImageRepositoryPath string `json:"imageRepositoryPath,omitempty"`
	// ImageTag is a string to specify which image tag to download
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Image Tag"
	ImageTag string `json:"imageTag,omitempty"`
}

// InitGlobal defines global information for initial deployment task
type InitGlobal struct {
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Init Image"
	InitialImage ImageInfo `json:"imageInfo,omitempty"`
}

// NodeInfo defines global information for nodes to be deployed
type NodeInfo struct {
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant Image Information"
	TenantImageInfo ImageInfo `json:"tenantImageInfo,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Registrar Image Information"
	RegistrarImageInfo ImageInfo `json:"registrarImageInfo,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Verifier Image Information"
	VerifierImageInfo ImageInfo `json:"verifierImageInfo,omitempty"`
}

// DeploymentSpec defines the desired state of Deployment
type DeploymentSpec struct {
	// Enabled is a boolean that allows to specify if controller based deployment
	// is enabled
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Enabled"
	Enabled bool `json:"enabled,omitempty"`
	// InitGlobal is a struct to define all information for the initial deployment
	// is enabled
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Init Global"
	InitGlobal InitGlobal `json:"initGlobal,omitempty"`
	// NodeInfo is a struct to define all information for nodes deployed:
	// - tenant
	// - registrar
	// - verifier
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Init Global"
	NodeInfo NodeInfo `json:"nodeInfo,omitempty"`
}

// DeploymentStatus defines the observed state of Deployment
type DeploymentStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Deployment is the Schema for the deployments API
type Deployment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DeploymentSpec   `json:"spec,omitempty"`
	Status DeploymentStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DeploymentList contains a list of Deployment
type DeploymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Deployment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Deployment{}, &DeploymentList{})
}
