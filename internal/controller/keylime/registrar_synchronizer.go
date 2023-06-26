package keylime

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/keylime/attestation-operator/pkg/client/registrar"
	"github.com/keylime/attestation-operator/pkg/client/verifier"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	defaultLoopInterval time.Duration = 30 * time.Second
)

type RegistrarSynchronizer struct {
	client.Client
	Scheme *runtime.Scheme

	Registrar    registrar.Client
	Verifier     verifier.Client
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
			r.reconcile(ctx)
			r.log.Info("reconciliation with keylime backend complete", "duration", time.Since(before))
		}
	}
	return nil
}

func (r *RegistrarSynchronizer) reconcile(ctx context.Context) {
	// TODO: implement
}

var _ manager.Runnable = &RegistrarSynchronizer{}

// SetupWithManager sets up the controller with the Manager.
func (r *RegistrarSynchronizer) SetupWithManager(mgr ctrl.Manager) error {
	r.log = mgr.GetLogger().WithValues("controller", "RegistrarSynchronizer")
	return mgr.Add(r)
}
