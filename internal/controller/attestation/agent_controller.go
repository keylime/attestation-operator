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
	"reflect"

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

// AgentReconciler reconciles a Agent object
type AgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Keylime kclient.Keylime
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var agentOrig attestationv1alpha1.Agent
	if err := r.Get(ctx, req.NamespacedName, &agentOrig); err != nil {
		l.Error(err, "unable to fetch agent")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// we are going to make a deep copy of the agent now and operate on this object
	agent := agentOrig.DeepCopy()

	// and we are always going to try to update the status depending if something changed now
	var deleted bool
	defer func() {
		if !deleted {
			if reflect.DeepEqual(agentOrig.Status, agent.Status) {
				l.Info("no status update necessary")
			} else {
				if err := r.Status().Update(ctx, agent); err != nil {
					// TODO: should fail the whole function with that error
					l.Error(err, "status update failed")
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
			return ctrl.Result{}, nil
		}
		l.Error(err, "unable to get agent from registrar")
		return ctrl.Result{}, err
	}
	agent.Status.Registrar = toRegistrarStatus(ragent)

	// get verifier status
	if agentOrig.Spec.Verifier != "" {
		vc, ok := r.Keylime.Verifier(agentOrig.Spec.Verifier)
		if !ok {
			// TODO: add an error state for that, nothing more we can do
			return ctrl.Result{}, nil
		}
		vagent, err := vc.GetAgent(ctx, agentOrig.Name)
		if err != nil {
			if http.IsNotFoundError(err) {
				// TODO: this is the case where we now need to add the agent to the verifier
				return ctrl.Result{}, nil
			}
			l.Error(err, "unable to get agent from verifier")
			return ctrl.Result{}, err
		}
		agent.Status.Verifier = toVerifierStatus(vagent)
	}

	return ctrl.Result{}, nil
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.Agent{}).
		Complete(r)
}
