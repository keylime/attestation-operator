// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package keylime

import (
	"context"
	"fmt"
	"os"

	"sync"
	"time"

	"github.com/go-logr/logr"
	kclient "github.com/keylime/attestation-operator/pkg/client"
	khttp "github.com/keylime/attestation-operator/pkg/client/http"

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

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (r *RegistrarSynchronizer) InitializeKeylimeClient(ctx context.Context) error {
	var registrarURL string
	var verifierURL string
	setupLog := ctrl.Log.WithName("setup")
	if val, ok := os.LookupEnv("KEYLIME_REGISTRAR_URL"); ok {
		if val == "" {
			err := fmt.Errorf("environment variable KEYLIME_REGISTRAR_URL is empty")
			setupLog.Error(err, "unable to determine URL for the keylime registrar")
			os.Exit(1)
		}
		registrarURL = val
	} else {
		err := fmt.Errorf("environment variable KEYLIME_REGISTRAR_URL not set")
		setupLog.Error(err, "unable to determine URL for the keylime registrar")
		os.Exit(1)
	}

	// TODO: we will actually need to detect and handle all verifiers
	// Ideally we would detect scaling up/down at runtime, but let alone dealing with multiple would be good
	if val, ok := os.LookupEnv("KEYLIME_VERIFIER_URL"); ok {
		if val == "" {
			err := fmt.Errorf("environment variable KEYLIME_VERIFIER_URL is empty")
			setupLog.Error(err, "unable to determine URL for the keylime registrar")
			os.Exit(1)
		}
		verifierURL = val
	} else {
		err := fmt.Errorf("environment variable KEYLIME_VERIFIER_URL not set")
		setupLog.Error(err, "unable to determine URL for the keylime registrar")
		os.Exit(1)
	}

	var clientCertFile, clientKeyFile string
	if val, ok := os.LookupEnv("KEYLIME_CLIENT_KEY"); ok {
		if val == "" {
			err := fmt.Errorf("environment variable KEYLIME_CLIENT_KEY is empty")
			setupLog.Error(err, "unable to determine client key file for the keylime client")
			os.Exit(1)
		}
		clientKeyFile = val
	} else {
		err := fmt.Errorf("environment variable KEYLIME_CLIENT_KEY not set")
		setupLog.Error(err, "unable to determine client key file for the keylime client")
		os.Exit(1)
	}
	if val, ok := os.LookupEnv("KEYLIME_CLIENT_CERT"); ok {
		if val == "" {
			err := fmt.Errorf("environment variable KEYLIME_CLIENT_CERT is empty")
			setupLog.Error(err, "unable to determine client cert file for the keylime client")
			os.Exit(1)
		}
		clientCertFile = val
	} else {
		err := fmt.Errorf("environment variable KEYLIME_CLIENT_CERT not set")
		setupLog.Error(err, "unable to determine client cert file for the keylime client")
		os.Exit(1)
	}

	tpmCertStore := os.Getenv("KEYLIME_TPM_CERT_STORE")

	// set this to info
	setupLog.Info("RegistrationSynchronizer: Certification Files Information", "CertFile", clientCertFile, "KeyFile", clientKeyFile)

	// if files don't exist, it is probable initialization of the secret is pending
	// return with no error
	if !fileExists(clientCertFile) {
		setupLog.Info("Certificate Client file doesn't exist", "CertFile", clientCertFile)
		return nil
	}
	if !fileExists(clientKeyFile) {
		setupLog.Info("Certificate Key file doesn't exist", "KeyFile", clientKeyFile)
		return nil
	}

	hc, err := khttp.NewKeylimeHTTPClient(
		khttp.ClientCertificate(clientCertFile, clientKeyFile),
		// TODO: unfortunately currently our server certs don't have the correct SANs
		// and for some reason that's not an issue for any of the other components
		// However, golang is very picky when it comes to that, and one cannot disable SAN verification individually
		khttp.InsecureSkipVerify(),
	)
	if err != nil {
		setupLog.Error(err, "unable to create Keylime HTTP client")
		os.Exit(1)
	}
	keylimeClient, err := kclient.New(ctx, ctrl.Log.WithName("keylime"), hc, registrarURL, []string{verifierURL}, tpmCertStore)
	if err != nil {
		setupLog.Error(err, "failed to create keylime client")
		os.Exit(1)
	}
	r.Keylime = keylimeClient
	return nil
}

// getLoopInterval returns the interval to run reconciliation
func (r *RegistrarSynchronizer) getLoopInterval() time.Duration {
	loopInterval := r.LoopInterval
	if loopInterval == 0 {
		loopInterval = defaultLoopInterval
	}
	return loopInterval
}

// Start implements manager.Runnable.
func (r *RegistrarSynchronizer) Start(ctx context.Context) error {
	t := time.NewTicker(r.getLoopInterval())
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
	r.InitializeKeylimeClient(ctx)
	if nil == r.Keylime {
		r.log.Info("Waiting for keylime client to be initialized ... ", "Interval", r.getLoopInterval())
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

	var wg sync.WaitGroup

	// delete all CRs which exist but are not in the registrar
	for _, cragent := range k8sList.Items {
		if _, ok := rmap[cragent.Name]; !ok {
			wg.Add(1)
			go func(cragent attestationv1alpha1.Agent) {
				r.deleteAgentCR(ctx, cragent)
				wg.Done()
			}(cragent)
		}
	}

	// add CRs for agent
	for _, uuid := range rlist {
		if _, ok := k8smap[uuid]; !ok {
			wg.Add(1)
			go func(uuid string) {
				r.addAgentCR(ctx, uuid)
				wg.Done()
			}(uuid)
		}
	}

	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-ctx.Done():
		r.log.Error(ctx.Err(), "reconcile: reconciliation loop timeout reached before processing of agent CRs could complete")
		return
	case <-waitCh:
		return
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
			Phase: attestationv1alpha1.AgentUndetermined,
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
