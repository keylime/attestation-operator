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

package attestation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
	kclient "github.com/keylime/attestation-operator/pkg/client"
	"github.com/keylime/attestation-operator/pkg/client/http"
	"github.com/keylime/attestation-operator/pkg/client/registrar"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
)

const (
	defaultReconcileInterval time.Duration = time.Second * 30
)

var (
	// this is a ZIP file with an 'empty.txt' file (which is - guess what - empty)
	defaultSecurePayload = []byte{
		0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x84,
		0xec, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x09, 0x00, 0x1c, 0x00, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e,
		0x74, 0x78, 0x74, 0x55, 0x54, 0x09, 0x00, 0x03, 0x5c, 0x39, 0xaf, 0x64,
		0x5c, 0x39, 0xaf, 0x64, 0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0xe8, 0x03,
		0x00, 0x00, 0x04, 0xe8, 0x03, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x1e,
		0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x84, 0xec, 0x56, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
		0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4,
		0x81, 0x00, 0x00, 0x00, 0x00, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x74,
		0x78, 0x74, 0x55, 0x54, 0x05, 0x00, 0x03, 0x5c, 0x39, 0xaf, 0x64, 0x75,
		0x78, 0x0b, 0x00, 0x01, 0x04, 0xe8, 0x03, 0x00, 0x00, 0x04, 0xe8, 0x03,
		0x00, 0x00, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x01, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// AgentReconciler reconciles a Agent object
type AgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ReconcileInterval time.Duration
	Keylime           kclient.Keylime
	SecurePayloadDir  string
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, retErr error) {
	l := log.FromContext(ctx)

	var agentOrig attestationv1alpha1.Agent
	if err := r.Get(ctx, req.NamespacedName, &agentOrig); err != nil {
		l.Error(err, "unable to fetch agent")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// TODO: handle agent deletes:
	// - needs to delete it from the verifier
	// - needs to delete it from the registrar

	// we are going to make a deep copy of the agent now and operate on this object
	agent := agentOrig.DeepCopy()
	agent.Status.Phase = attestationv1alpha1.AgentUndetermined
	agent.Status.PhaseReason = attestationv1alpha1.UnsuccessfulChecks
	agent.Status.PhaseMessage = "No checks with the keylime registrar or verifier have been performed yet"

	// and we are always going to try to update the status depending if something changed now
	var deleted bool
	defer func() {
		if !deleted {
			if reflect.DeepEqual(agentOrig.Status, agent.Status) {
				l.Info("no status update necessary")
			} else {
				if err := r.Status().Update(ctx, agent); err != nil {
					l.Error(err, "status update failed")
					retErr = err
					return
				}
				l.Info("status update successful")
			}
		}
	}()

	// get registrar status
	ragent, err := r.Keylime.Registrar().GetAgent(ctx, agentOrig.Name)
	if err != nil {
		if http.IsNotFoundError(err) {
			// delete the resource if it does not exist in the registrar any longer
			deleted = true
			if err := r.Delete(ctx, &agentOrig); err != nil {
				l.Error(err, "unable to delete agent")
				return ctrl.Result{}, err
			}
			// do not requeue here, we are not interested any longer
			return ctrl.Result{}, nil
		}
		l.Error(err, "unable to get agent from registrar")
		agent.Status.PhaseMessage = fmt.Sprintf("Check for the agent with the registrar failed: %s", err)
		return ctrl.Result{}, err
	}
	agent.Status.Registrar = toRegistrarStatus(ragent)
	agent.Status.Phase = attestationv1alpha1.AgentRegistered
	agent.Status.PhaseReason = attestationv1alpha1.RegistrarCheckSuccess
	agent.Status.PhaseMessage = "The agent was found in the registrar"

	// we are now in a position to determine the pod and node of the agent if the agent is running inside of the Kubernetes cluster
	// we need to try to find the pod name only if it has not been set before, or in the case that its IP and/or port changed (in which case this is probably a new pod)
	if agent.Status.Pod == "" || agent.Status.Node == "" || agentOrig.Status.Registrar.AgentIP != ragent.IP || agentOrig.Status.Registrar.AgentPort != ragent.Port {
		// TODO: optimize this - this is potentially super slow otherwise - could easily be a configuration item to look in a certain namespace and/or label selector
		var podList corev1.PodList
		if err := r.List(ctx, &podList, &client.ListOptions{}); err != nil {
			l.Error(err, "unable to get pods")
			return ctrl.Result{}, err
		}
		var found bool
		for _, pod := range podList.Items {
			if pod.Status.PodIP == ragent.IP {
				found = true
				agent.Status.Pod = pod.Namespace + string('/') + pod.Name
				// TODO: double-check if this is reliable, I believe it is in our case
				agent.Status.Node = pod.Spec.NodeName
				break
			}
		}
		// ensure to unset these if not found at all
		// NOTE: this could be perfectly fine, as there is no requirement for the agent to be running inside of the Kubernetes cluster
		// TODO: add condition for this
		if !found {
			agent.Status.Pod = ""
			agent.Status.Node = ""
		}
	}

	// perform EK certificate verification
	// this is only possible now as we have the registrar agent status now
	if agentOrig.Spec.EKCertificateStore.EnableVerification {
		// move the phase forward
		agent.Status.Phase = attestationv1alpha1.AgentEKVerification

		// we read the CA pool from the secret first if needed
		var pool *x509.CertPool
		if agentOrig.Spec.EKCertificateStore.SecretName != "" {
			var err error
			pool, err = r.readCAPoolFromSecret(ctx, agentOrig.Spec.EKCertificateStore.SecretName)
			if err != nil {
				l.Error(err, "failed to read CA pool from secret", "secret", agentOrig.Spec.EKCertificateStore.SecretName)
				agent.Status.PhaseReason = attestationv1alpha1.EKVerificationProcessingError
				agent.Status.PhaseMessage = fmt.Sprintf("Reading CA pool from secret '%s' failed: %s", agentOrig.Spec.EKCertificateStore.SecretName, err)
				ekVerified := false
				agent.Status.EKCertificateVerified = &ekVerified
				return ctrl.Result{}, err
			}
		}

		ekVerified, ekAuthority := r.Keylime.VerifyEK(ragent.EKCert, pool)
		agent.Status.EKCertificateVerified = &ekVerified
		agent.Status.EKCertificateAuthority = ekAuthority
		if ekVerified {
			agent.Status.PhaseReason = attestationv1alpha1.EKVerificationSuccess
			agent.Status.PhaseMessage = "The EK certificate verification was successful"
		} else {
			agent.Status.PhaseReason = attestationv1alpha1.EKVerificationFailure
			agent.Status.PhaseMessage = "The EK certificate verification failed"
		}
	}

	// detect change in verifier and add/delete the agent to/from a verifier
	if detectVerifierChange(&agentOrig) {
		// if the agent was part of a verifier before, delete it from there
		if agentOrig.Status.VerifierName != "" {
			vc, ok := r.Keylime.Verifier(agentOrig.Status.VerifierName)
			if !ok {
				agent.Status.VerifierName = ""
			} else {
				if err := vc.DeleteAgent(ctx, agentOrig.Name); err != nil && !http.IsNotFoundError(err) {
					l.Error(err, "failed to delete agent from verifier")
					return ctrl.Result{}, err
				}
				agent.Status.VerifierName = ""
			}
		}

		// if the new verifier is not empty, we want to add it to the new verifier
		if agentOrig.Spec.VerifierName != "" {
			vc, ok := r.Keylime.Verifier(agentOrig.Spec.VerifierName)
			if !ok {
				agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
				agent.Status.PhaseReason = attestationv1alpha1.InvalidVerifier
				agent.Status.PhaseMessage = fmt.Sprintf("No verifier under the name of '%s' could be found", agentOrig.Spec.VerifierName)
				return ctrl.Result{
					Requeue:      true,
					RequeueAfter: r.ReconcileInterval,
				}, nil
			}

			// check if the agent is already there, because we'll delete it first then before we add it again
			// this could happen in multiple scenarios:
			// - if we previously didn't get to delete the agent correctly
			// - if it was added out of band (for example by the keylime_tenant CLI)
			// - if we are simply changing the secure payload to be delivered
			vagent, err := vc.GetAgent(ctx, agentOrig.Name)
			if err != nil && !http.IsNotFoundError(err) {
				l.Error(err, "failed to check verifier for previously existing agent")
				return ctrl.Result{}, err
			}
			if vagent != nil {
				if err := vc.DeleteAgent(ctx, agentOrig.Name); err != nil {
					l.Error(err, "failed to delete previously existing agent from verifier")
					return ctrl.Result{}, err
				}
			}

			securePayload := defaultSecurePayload
			if agentOrig.Spec.SecurePayload.EnableSecurePayload {
				var err error
				securePayload, err = r.readSecurePayloadFromSecret(ctx, agentOrig.Spec.SecurePayload.SecretName)
				if err != nil {
					l.Error(err, "failed to read secure payload", "secret", agentOrig.Spec.SecurePayload.SecretName)
					return ctrl.Result{}, err
				}
			}

			// this is the case where we now need to add the agent to the verifier
			if err := r.Keylime.AddAgentToVerifier(ctx, ragent, vc, securePayload); err != nil {
				l.Error(err, "failed to add agent to verifier")
				agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
				agent.Status.PhaseReason = attestationv1alpha1.AddToVerifierError
				agent.Status.PhaseMessage = fmt.Sprintf("Failed to add agent to verifier: %s", err)
				agent.Status.VerifierName = ""
				// no need to return with the error here
				// TODO: we could return with an error if it was purely a network issue or some other non-fatal errors which could get retried
				// return ctrl.Result{}, err
			} else {
				agent.Status.VerifierName = agentOrig.Spec.VerifierName
			}
		}
	}

	if agent.Status.VerifierName != "" {
		vc, ok := r.Keylime.Verifier(agent.Status.VerifierName)
		if !ok {
			// this verifier can no longer be found, we'll reset the status of the verifier and reconcile
			agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
			agent.Status.PhaseReason = attestationv1alpha1.InvalidVerifier
			agent.Status.PhaseMessage = fmt.Sprintf("No verifier under the name of '%s' could be found", agent.Status.VerifierName)
			agent.Status.VerifierName = ""
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: r.ReconcileInterval,
			}, nil
		}

		vagent, err := vc.GetAgent(ctx, agentOrig.Name)
		if err != nil {
			if http.IsNotFoundError(err) {
				// somebody deleted the agent out of band, we'll reset the status verifier name and reconcile
				l.Error(err, "agent not in verifier any longer")
				agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
				agent.Status.PhaseReason = attestationv1alpha1.UnsuccessfulChecks
				agent.Status.PhaseMessage = fmt.Sprintf("agent no longer exists in verifier: %s", err)
				agent.Status.VerifierName = ""
				return ctrl.Result{
					Requeue:      true,
					RequeueAfter: r.ReconcileInterval,
				}, nil
			}
			l.Error(err, "unable to get agent from verifier")
			agent.Status.PhaseReason = attestationv1alpha1.UnsuccessfulChecks
			agent.Status.PhaseMessage = fmt.Sprintf("Check for the agent with the verifier failed: %s", err)
			return ctrl.Result{}, err
		}
		agent.Status.Verifier = toVerifierStatus(vagent)
		agent.Status.Phase = attestationv1alpha1.AgentVerifying
		agent.Status.PhaseReason = attestationv1alpha1.VerifierCheckSuccess
		agent.Status.PhaseMessage = "The agent was found in the verifier"
	}

	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: r.ReconcileInterval,
	}, nil
}

func (r *AgentReconciler) readCAPoolFromSecret(ctx context.Context, secretName string) (*x509.CertPool, error) {
	// TODO: implement
	pool := x509.NewCertPool()
	return pool, nil
}

func (r *AgentReconciler) readSecurePayloadFromSecret(ctx context.Context, secretName string) ([]byte, error) {
	// TODO: implement
	if secretName != "" {
		return defaultSecurePayload, nil
	} else if r.SecurePayloadDir != "" {
		return defaultSecurePayload, nil
	}

	return nil, fmt.Errorf("neither a secret name is provided nor is the controller configured with KEYLIME_SECURE_PAYLOAD_DIR")
}

func toRegistrarStatus(a *registrar.Agent) *attestationv1alpha1.RegistrarStatus {
	return &attestationv1alpha1.RegistrarStatus{
		AIK:       a.AIK,
		EK:        a.EK,
		EKCert:    a.EKCert.Raw,
		AgentCert: a.MTLSCert.Raw,
		AgentIP:   a.IP,
		AgentPort: a.Port,
		RegCount:  a.RegCount,
	}
}

func toVerifierStatus(a *verifier.Agent) *attestationv1alpha1.VerifierStatus {
	var lastReceivedQuote, lastSuccessfulAttestation metav1.Time
	if a.LastReceivedQuote != nil {
		lastReceivedQuote = metav1.NewTime(*a.LastReceivedQuote)
	}
	if a.LastSuccessfulAttestation != nil {
		lastSuccessfulAttestation = metav1.NewTime(*a.LastSuccessfulAttestation)
	}
	var metadata string
	metadataBytes, err := json.Marshal(a.MetaData)
	if err == nil {
		metadata = string(metadataBytes)
	}
	return &attestationv1alpha1.VerifierStatus{
		OperationalState:            a.OperationalState.String(),
		OperationalStateDescription: a.OperationalState.Description(),
		V:                           a.V,
		TPMPolicy:                   a.TPMPolicy,
		VTPMPolicy:                  a.VTPMPolicy,
		MetaData:                    metadata,
		HasMBRefState:               a.HasMBRefState,
		HasRuntimePolicy:            a.HasRuntimePolicy,
		AcceptTPMHashAlgs:           a.AcceptTPMHashAlgs,
		AcceptTPMEncryptionAlgs:     a.AcceptTPMEncryptionAlgs,
		AcceptTPMSigningAlgs:        a.AcceptTPMSigningAlgs,
		HashAlg:                     a.HashAlg,
		EncryptionAlg:               a.EncryptionAlg,
		SigningAlg:                  a.SigningAlg,
		SeverityLevel:               a.SeverityLevel,
		LastEventID:                 a.LastEventID,
		AttestationCount:            a.AttestationCount,
		LastReceivedQuote:           lastReceivedQuote,
		LastSuccessfulAttestation:   lastSuccessfulAttestation,
	}
}

func detectVerifierChange(a *attestationv1alpha1.Agent) bool {
	// the most straight forward case: the status and spec of the verifier are not the same anymore
	if a.Spec.VerifierName != a.Status.VerifierName {
		return true
	}

	// there is a difference between the expected secure payload in the spec than the one that was delivered
	// this qualifies as a verifier change and needs to trigger that the agent gets deleted and added again
	// to a verifier
	if a.Spec.SecurePayload.Status() != a.Status.SecurePayloadDelivered {
		return true
	}

	// everything else does *not* constitute a verifier change (at least not for the detection mechanism)
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ReconcileInterval == 0 {
		r.ReconcileInterval = defaultReconcileInterval
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.Agent{}).
		Complete(r)
}
