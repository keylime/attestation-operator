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

// AgentReconciler reconciles a Agent object
type AgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ReconcileInterval time.Duration
	Keylime           kclient.Keylime
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/finalizers,verbs=update

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

	// get verifier status
	if agentOrig.Spec.Verifier != "" {
		vc, ok := r.Keylime.Verifier(agentOrig.Spec.Verifier)
		if !ok {
			agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
			agent.Status.PhaseReason = attestationv1alpha1.InvalidVerifier
			agent.Status.PhaseMessage = fmt.Sprintf("No verifier under the name of '%s' could be found", agentOrig.Spec.Verifier)
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: r.ReconcileInterval,
			}, nil
		}
		vagent, err := vc.GetAgent(ctx, agentOrig.Name)
		if err != nil {
			if http.IsNotFoundError(err) {
				// this is the case where we now need to add the agent to the verifier
				if err := r.Keylime.AddAgentToVerifier(ctx, ragent, vc); err != nil {
					l.Error(err, "failed to add agent to verifier")
					agent.Status.Phase = attestationv1alpha1.AgentUnschedulable
					agent.Status.PhaseReason = attestationv1alpha1.AddToVerifierError
					agent.Status.PhaseMessage = fmt.Sprintf("Failed to add agent to verifier: %s", err)
					// no need to return with the error here
					// TODO: we could return with an error if it was purely a network issue or some other non-fatal errors which could get retried
					// return ctrl.Result{}, err
				}
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

// SetupWithManager sets up the controller with the Manager.
func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ReconcileInterval == 0 {
		r.ReconcileInterval = defaultReconcileInterval
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.Agent{}).
		Complete(r)
}
