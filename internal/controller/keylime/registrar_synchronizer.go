// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package keylime

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	kclient "github.com/keylime/attestation-operator/pkg/client"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultLoopInterval time.Duration = 30 * time.Second
)

type RegistrarSynchronizer struct {
	client.Client
	Scheme *runtime.Scheme

	Keylime      kclient.Keylime
	LoopInterval time.Duration

	log logr.Logger
}

// Start implements manager.Runnable.
func (r *RegistrarSynchronizer) Start(ctx context.Context) error {
	loopInterval := r.LoopInterval
	if loopInterval == 0 {
		loopInterval = defaultLoopInterval
	}
	t := time.NewTicker(loopInterval)
	defer t.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-t.C:
			before := time.Now()
			subCtx, cancel := context.WithTimeout(ctx, time.Minute)
			r.reconcile(subCtx)
			cancel()
			r.log.Info("reconciliation with keylime backend complete", "duration", time.Since(before))
		}
	}
	return nil
}

func (r *RegistrarSynchronizer) reconcile(ctx context.Context) {
	// get a list of agent CRDs
	var k8sList attestationv1alpha1.AgentList
	if err := r.Client.List(ctx, &k8sList); err != nil {
		r.log.Error(err, "reconcile: failed to get list of agent CRs")
		return
	}
	k8smap := make(map[string]struct{}, len(k8sList.Items))
	for _, cragent := range k8sList.Items {
		k8smap[cragent.Name] = struct{}{}
	}

	// get a list of registered agents from the keylime backend
	rlist, err := r.Keylime.Registrar().ListAgents(ctx)
	if err != nil {
		r.log.Error(err, "reconcile: failed to get list of agent")
		return
	}
	rmap := make(map[string]struct{}, len(rlist))
	for _, uuid := range rlist {
		rmap[uuid] = struct{}{}
	}

	// delete all CRs which exist but are not in the registrar
	for _, cragent := range k8sList.Items {
		if _, ok := rmap[cragent.Name]; !ok {
			go r.deleteAgentCR(ctx, cragent)
		}
	}

	// add CRs for agent
	for _, uuid := range rlist {
		if _, ok := k8smap[uuid]; !ok {
			go r.addAgentCR(ctx, uuid)
		}
	}
}

func (r *RegistrarSynchronizer) deleteAgentCR(ctx context.Context, obj attestationv1alpha1.Agent) {
	// TODO: should also try to delete it from the verifier just in case if the verifier is set
	if err := r.Client.Delete(ctx, &obj); err != nil {
		r.log.Error(err, "reconcile: failed to delete agent CR", "name", obj.Name)
		return
	}
	r.log.Info("reconcile: deleted agent CR as it is no longer in the registrar", "name", obj.Name)
}

func (r *RegistrarSynchronizer) addAgentCR(ctx context.Context, uuid string) {
	obj := attestationv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{
			Name: uuid,
		},
		// we leave this empty and leave it to the real controller to handle this
		Spec: attestationv1alpha1.AgentSpec{},
		Status: attestationv1alpha1.AgentStatus{
			State: attestationv1alpha1.AgentUnknown,
			// the real controller will populate this
			Registrar: nil,
			Verifier:  nil,
		},
	}

	if err := r.Client.Create(ctx, &obj); err != nil {
		r.log.Error(err, "reconcile: failed to add agent CR", "name", obj.Name)
		return
	}
	r.log.Info("reconcile: added agent CR", "name", obj.Name)
}

var _ manager.Runnable = &RegistrarSynchronizer{}

// SetupWithManager sets up the controller with the Manager.
func (r *RegistrarSynchronizer) SetupWithManager(mgr ctrl.Manager) error {
	r.log = mgr.GetLogger().WithValues("controller", "RegistrarSynchronizer")
	return mgr.Add(r)
}
