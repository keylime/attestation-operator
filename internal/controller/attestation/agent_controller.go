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
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	khttp "github.com/keylime/attestation-operator/pkg/client/http"
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
	PodNamespace      string
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (r *AgentReconciler) InitializeKeylimeClient() error {
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

	var agentReconcileInterval time.Duration
	if val, ok := os.LookupEnv("KEYLIME_AGENT_RECONCILE_INTERVAL_DURATION"); ok {
		var err error
		agentReconcileInterval, err = time.ParseDuration(val)
		if err != nil {
			setupLog.Error(fmt.Errorf("environment variable KEYLIME_AGENT_RECONCILE_INTERVAL_DURATION did not contain a duration string: %w", err), "unable to parse agent reconcile interval duration")
			os.Exit(1)
		}
		r.ReconcileInterval = agentReconcileInterval
	}

	tpmCertStore := os.Getenv("KEYLIME_TPM_CERT_STORE")
	r.SecurePayloadDir = os.Getenv("KEYLIME_SECURE_PAYLOAD_DIR")
	r.PodNamespace = os.Getenv("POD_NAMESPACE")

	// we are going to reuse this context in several places
	// so we'll create it already here
	ctx := ctrl.SetupSignalHandler()

	// set this to info
	setupLog.Info("AgentController: Certification Files Information", "CertFile", clientCertFile, "KeyFile", clientKeyFile)

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

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=agents/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

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

	// In case keylime client not created ... it might be waiting for secret creation
	r.InitializeKeylimeClient()
	if nil == r.Keylime {
		l.Info("Waiting for keylime client to be initialized ... " +
			"will attempt again in " + string(r.ReconcileInterval))
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: r.ReconcileInterval,
		}, nil
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

		// and initialize the corresponding status struct
		// we only want that if the verification is enabled
		agent.Status.EKCertificate = &attestationv1alpha1.EKCertificate{}

		// we read the CA pool from the secret first if needed
		var rootPool, intermediatePool *x509.CertPool
		if agentOrig.Spec.EKCertificateStore.SecretName != "" {
			var err error
			rootPool, intermediatePool, err = r.readCAPoolFromSecret(ctx, agentOrig.Spec.EKCertificateStore.SecretName)
			if err != nil {
				l.Error(err, "failed to read CA pool from secret", "secret", agentOrig.Spec.EKCertificateStore.SecretName)
				agent.Status.PhaseReason = attestationv1alpha1.EKVerificationProcessingError
				agent.Status.PhaseMessage = fmt.Sprintf("Reading CA pool from secret '%s' failed: %s", agentOrig.Spec.EKCertificateStore.SecretName, err)
				return ctrl.Result{}, err
			}
		}

		ekVer, ekErr := r.Keylime.VerifyEK(ragent.EKCert, rootPool, intermediatePool)
		agent.Status.EKCertificate.Verified = ekVer.Verified
		agent.Status.EKCertificate.AuthorityChains = ekVer.AuthorityChains

		if ekVer.SubjectAlternativeNames != nil {
			agent.Status.EKCertificate.TPM = &attestationv1alpha1.TPM{
				Manufacturer:    ekVer.SubjectAlternativeNames.TPMManufacturer.String(),
				Model:           ekVer.SubjectAlternativeNames.TPMModel.String(),
				FirmwareVersion: ekVer.SubjectAlternativeNames.TPMVersion.String(),
			}
		}
		if ekVer.SubjectDirectoryAttributes != nil {
			if agent.Status.EKCertificate.TPM == nil {
				agent.Status.EKCertificate.TPM = &attestationv1alpha1.TPM{}
			}
			agent.Status.EKCertificate.TPM.Specification = &attestationv1alpha1.TPMSpecification{
				Family:   ekVer.SubjectDirectoryAttributes.Family,
				Level:    ekVer.SubjectDirectoryAttributes.Level,
				Revision: ekVer.SubjectDirectoryAttributes.Revision,
			}
		}

		if ekVer.Verified {
			agent.Status.PhaseReason = attestationv1alpha1.EKVerificationSuccess
			agent.Status.PhaseMessage = "The EK certificate verification was successful"
		} else {
			agent.Status.PhaseReason = attestationv1alpha1.EKVerificationFailure
			agent.Status.PhaseMessage = fmt.Sprintf("The EK certificate verification failed: %s", ekErr)
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
			agentVerify := false
			if agentOrig.Spec.SecurePayload.EnableSecurePayload {
				var err error
				securePayload, err = r.readSecurePayloadFromSecret(ctx, agentOrig.Spec.SecurePayload.SecretName)
				if err != nil {
					l.Error(err, "failed to read secure payload", "secret", agentOrig.Spec.SecurePayload.SecretName)
					return ctrl.Result{}, err
				}
				agentVerify = agentOrig.Spec.SecurePayload.AgentVerify
			}

			// this is the case where we now need to add the agent to the verifier
			if err := r.Keylime.AddAgentToVerifier(ctx, ragent, vc, securePayload, agentVerify); err != nil {
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
				agent.Status.SecurePayloadDelivered = agentOrig.Spec.SecurePayload.Status()
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

func (r *AgentReconciler) readCAPoolFromSecret(ctx context.Context, secretName string) (*x509.CertPool, *x509.CertPool, error) {
	rp := x509.NewCertPool()
	ip := x509.NewCertPool()

	var secret corev1.Secret
	secName, secNamespace := r.splitSecretName(secretName)
	if err := r.Get(ctx, client.ObjectKey{Name: secName, Namespace: secNamespace}, &secret); err != nil {
		return nil, nil, err
	}

	for _, pemCerts := range secret.Data {
		p, restPEM := pem.Decode(pemCerts)
		for p != nil {
			if p.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(p.Bytes)
				if err == nil {
					if isSelfSignedCert(cert) {
						rp.AddCert(cert)
					} else {
						ip.AddCert(cert)
					}
				}
			}
			p, restPEM = pem.Decode(restPEM)
		}
	}

	return rp, ip, nil
}

// isSelfSignedCert checks if the given cert is a self-signed certificate
// TODO: duplicated from client.go
func isSelfSignedCert(cert *x509.Certificate) bool {
	// Root CAs must have the same CN for Subject and Issuer
	// so we don't bother for the rest
	if cert.Issuer.CommonName == cert.Subject.CommonName {
		err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		return err == nil
	}
	return false
}

// splitSecretName splits the secretName into Name and Namespace. It is expected that the namespace is separated by a '/'.
// If no '/' occurs, then it is expected to be just the Name. Namespace will be empty.
func (r *AgentReconciler) splitSecretName(secretName string) (string, string) {
	v := strings.SplitN(secretName, "/", 2)
	if len(v) >= 2 {
		return v[1], v[0]
	}
	return secretName, r.PodNamespace
}

func (r *AgentReconciler) readSecurePayloadFromSecret(ctx context.Context, secretName string) ([]byte, error) {
	if secretName != "" {
		var secret corev1.Secret
		secName, secNamespace := r.splitSecretName(secretName)

		if err := r.Get(ctx, client.ObjectKey{Name: secName, Namespace: secNamespace}, &secret); err != nil {
			return nil, err
		}

		zipBuf := &bytes.Buffer{}
		zipWriter := zip.NewWriter(zipBuf)

		for fileName, fileContents := range secret.Data {
			if err := func(fileName string, fileContents []byte) error {
				w, err := zipWriter.Create(fileName)
				if err != nil {
					return err
				}
				if _, err := w.Write(fileContents); err != nil {
					return err
				}
				return nil
			}(fileName, fileContents); err != nil {
				return nil, fmt.Errorf("failed to compress payload at file name '%s': %w", fileName, err)
			}
		}

		if err := zipWriter.Close(); err != nil {
			return nil, fmt.Errorf("failed to create zip payload: %w", err)
		}

		return zipBuf.Bytes(), nil

	} else if r.SecurePayloadDir != "" {
		// we do the same as for secrets: we only allow a single directory, and we will ignore directories
		dir, err := os.Open(r.SecurePayloadDir)
		if err != nil {
			return nil, fmt.Errorf("failed to open directory %s: %w", r.SecurePayloadDir, err)
		}
		defer dir.Close()
		dirEntries, err := dir.Readdirnames(0)
		if err != nil {
			return nil, fmt.Errorf("failed to list directory entries %s: %w", r.SecurePayloadDir, err)
		}

		zipBuf := &bytes.Buffer{}
		zipWriter := zip.NewWriter(zipBuf)

		for _, dirEntry := range dirEntries {
			if err := func(dirEntry string) error {
				filePath := filepath.Join(r.SecurePayloadDir, dirEntry)
				f, err := os.Open(filePath)
				if err != nil {
					return fmt.Errorf("failed to open file %s: %w", filePath, err)
				}
				defer f.Close()
				st, err := f.Stat()
				if err != nil {
					return fmt.Errorf("failed to stat file %s: %w", filePath, err)
				}
				if st.IsDir() {
					return nil
				}
				fileContents, err := io.ReadAll(bufio.NewReader(f))
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", filePath, err)
				}

				w, err := zipWriter.Create(dirEntry)
				if err != nil {
					return err
				}
				if _, err := w.Write(fileContents); err != nil {
					return err
				}

				return nil
			}(dirEntry); err != nil {
				return nil, fmt.Errorf("failed to compress payload at file name '%s': %w", dirEntry, err)
			}
		}

		if err := zipWriter.Close(); err != nil {
			return nil, fmt.Errorf("failed to create zip payload: %w", err)
		}

		return zipBuf.Bytes(), nil
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
