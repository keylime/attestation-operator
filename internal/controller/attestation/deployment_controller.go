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

package attestation

import (
	"context"
	"errors"
	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

// Time in seconds to wait for init job
// TODO: set this configurable in CRD
const DEFAULT_WAIT_INIT_JOB = 30

// DeploymentReconciler reconciles a Deployment object
type DeploymentReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	InitJobCounter uint16
	InitJob        *batchv1.Job
	ContainerName  string
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=deployments/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=deployments/finalizers,verbs=update
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=jobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update
//+kubebuilder:rbac:groups=core,resources=pods/exec,verbs=get;list;watch;create;update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,resourceNames=anyuid,verbs=use

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Deployment object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *DeploymentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	SetLogInstance(l)

	// In case init job counter is enabled, reconcile after one second and decrease counter
	if r.InitJobCounter > 0 {
		l.Info("Waiting for initial job", "Pending count", r.InitJobCounter)
		r.InitJobCounter -= 1
		return ctrl.Result{RequeueAfter: time.Duration(1) * time.Second}, nil
	}

	deployment := &attestationv1alpha1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: req.NamespacedName.Namespace,
			Name:      req.NamespacedName.Name,
		},
	}
	err := r.Get(ctx, req.NamespacedName, deployment)
	if err != nil {
		l.Error(err, "Attestation Deployment resource not found")
		return ctrl.Result{}, err
	}

	err = r.deployComponents(deployment, req)
	if err != nil {
		l.Error(err, "Unable to deploy components")
	}
	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *DeploymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.Deployment{}).
		Owns(&corev1.Secret{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}

// deployComponents will parse Attestation Deployment spec and will launch
// specified nodes in CRD
func (r *DeploymentReconciler) deployComponents(deployment *attestationv1alpha1.Deployment, req ctrl.Request) error {
	l := GetLogInstance()
	//TODO: perform deployment of the different components here
	if deployment.Spec.Enabled == true {
		l.Info("Deployment is enabled")
		err := r.deployInitTasks(deployment, req)
		if err != nil {
			l.Error(err, "Unable to deploy initialization tasks")
			return err
		}
		err = r.deployKeylimeNodes(deployment, req)
		if err != nil {
			l.Error(err, "Unable to deploy initialization tasks")
			return err
		}
	} else {
		l.Info("Deployment is not enabled")
	}
	return nil
}

// createCAPasswordSecret
func (r *DeploymentReconciler) createCAPasswordSecret(deployment *attestationv1alpha1.Deployment, req ctrl.Request) error {
	nameSpace := getCAPasswordSecretNamespace(req)
	name := getCAPasswordSecretName(req)
	search := types.NamespacedName{
		Namespace: nameSpace,
		Name:      name,
	}
	// CA Password Secret
	secretCaPassword := &corev1.Secret{}
	err := r.Get(context.Background(), search, secretCaPassword)
	if err == nil {
		GetLogInstance().Info("CA Password Secret is already there", "Namespace", secretCaPassword.Namespace,
			"Name", secretCaPassword.Name, "Amount of Secrets", len(secretCaPassword.StringData))
		return nil
	}
	GetLogInstance().Info("Creating CA Password Secret", "Namespace", secretCaPassword.Namespace, "Name", secretCaPassword.Name)
	secretCaPassword = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nameSpace,
			Name:      name, //TODO: set as configurable
		},
	}
	err = ctrl.SetControllerReference(deployment, secretCaPassword, r.Scheme)
	if err != nil {
		GetLogInstance().Error(err, "Unable to set CA password secret controller reference")
		return err
	}
	err = r.Create(context.Background(), secretCaPassword)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create CA password secret, maybe it already exists?")
	}
	secretCaPassword.StringData = make(map[string]string)
	secretCaPassword.StringData["KEYLIME_CA_PASSWORD"] = NewRandPasswordGen().num(32) // TODO: set key and length as configurable
	err = r.Update(context.Background(), secretCaPassword)
	if err != nil {
		GetLogInstance().Error(err, "Unable to update CA password secret")
		return err
	}
	return nil
}

// createCertsSecret will create certs secret if it does not exist
func (r *DeploymentReconciler) createCertsSecret(deployment *attestationv1alpha1.Deployment, req ctrl.Request) (*corev1.Secret, error) {
	nameSpace := getCertsSecretNamespace(req)
	name := getCertsSecretName(req)
	search := types.NamespacedName{
		Namespace: nameSpace,
		Name:      name,
	}

	// Certificates Secret
	secretCerts := &corev1.Secret{}
	err := r.Get(context.Background(), search, secretCerts)
	if err == nil {
		GetLogInstance().Info("Certificates Secret is already there", "Namespace", secretCerts.Namespace,
			"Name", secretCerts.Name, "Amount of Secrets", len(secretCerts.StringData))
		return nil, nil
	}
	GetLogInstance().Info("Creating Certificates Secret", "Namespace", secretCerts.Namespace, "Name", secretCerts.Name)
	secretCerts = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nameSpace,
			Name:      name, //TODO: set as configurable
		},
	}
	err = ctrl.SetControllerReference(deployment, secretCerts, r.Scheme)
	if err != nil {
		GetLogInstance().Error(err, "Unable to set certificates secret controller reference")
		return nil, err
	}
	err = r.Create(context.Background(), secretCerts)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create certificate secret, maybe it already exists?")
	}
	return secretCerts, err
}

// getTPMCertsSecretName returns name of the TPM certificates secret
func getTPMCertsSecretName(req ctrl.Request) string {
	return req.NamespacedName.Name + "-tpm-cert-store"
}

// getTPMCertsSecretNamespace returns namespace of the TPM certificates secret
func getTPMCertsSecretNamespace(req ctrl.Request) string {
	return req.NamespacedName.Namespace
}

// getCertsSecretName returns name of the certificates secret
func getCertsSecretName(req ctrl.Request) string {
	return req.NamespacedName.Name + "-certs"
}

// getTPMCertsSecretNamespace returns namespace of the TPM certificates secret
func getCertsSecretNamespace(req ctrl.Request) string {
	return req.NamespacedName.Namespace
}

// getCAPasswordSecretName returns name of the CA password secret
func getCAPasswordSecretName(req ctrl.Request) string {
	return req.NamespacedName.Name + "-ca-password" //TODO: set as configurable
}

// getCAPasswordNamespace returns namespace of the CA password secret
func getCAPasswordSecretNamespace(req ctrl.Request) string {
	return req.NamespacedName.Namespace
}

// createTPMCertsSecret will create TPM certs secret if it does not exist
func (r *DeploymentReconciler) createTPMCertsSecret(deployment *attestationv1alpha1.Deployment, req ctrl.Request) (*corev1.Secret, error) {
	nameSpace := getTPMCertsSecretNamespace(req)
	name := getTPMCertsSecretName(req)
	search := types.NamespacedName{
		Namespace: nameSpace,
		Name:      name,
	}
	// TPM Certificates Secret
	secretTPMCerts := &corev1.Secret{}
	err := r.Get(context.Background(), search, secretTPMCerts)
	if err == nil {
		GetLogInstance().Info("TPM Certificates Secret is already there", "Namespace", secretTPMCerts.Namespace,
			"Name", secretTPMCerts.Name)
		return nil, nil
	}
	GetLogInstance().Info("Creating TPM Secret", "Namespace", secretTPMCerts.Namespace, "Name", secretTPMCerts.Name)
	secretTPMCerts = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nameSpace,
			Name:      name, //TODO: set as configurable
		},
	}
	err = ctrl.SetControllerReference(deployment, secretTPMCerts, r.Scheme)
	if err != nil {
		GetLogInstance().Error(err, "Unable to set TPM secret controller reference")
		return nil, err
	}
	err = r.Create(context.Background(), secretTPMCerts)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create TPM secret, maybe it already exists?")
	}
	return secretTPMCerts, err
}

// createInitialJob will create initial job
func (r *DeploymentReconciler) createInitialJob(deployment *attestationv1alpha1.Deployment, req ctrl.Request) error {
	// Initial Job
	nameSpace := req.NamespacedName.Namespace
	jobName := req.NamespacedName.Name + "-init-job"
	containerName := req.NamespacedName.Name + "-init-job-container"
	initJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nameSpace,
			Name:      jobName,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &[]int32{1}[0],
			Completions:  &[]int32{1}[0],
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Image:          getInitJobImageNameAndTag(deployment),
							Name:           containerName,
							Ports:          []corev1.ContainerPort{},
							LivenessProbe:  nil,
							ReadinessProbe: nil,
							VolumeMounts:   nil,
							Resources:      corev1.ResourceRequirements{},
							Command:        getInitJobCommands(),
							Env:            getInitJobEnvVars(req),
						},
					},
					RestartPolicy:      "Never",
					ServiceAccountName: "attestation-operator-controller-manager",
				},
			},
		},
	}
	search := types.NamespacedName{
		Namespace: nameSpace,
		Name:      jobName,
	}
	err := r.Get(context.Background(), search, initJob)
	if err == nil {
		GetLogInstance().Info("Init Job is already there", "Namespace", initJob.Namespace, "Name", initJob.Name)
		return nil
	}
	GetLogInstance().Info("Creating Init Job", "Namespace", initJob.Namespace, "Name", initJob.Name)
	err = ctrl.SetControllerReference(deployment, initJob, r.Scheme)
	if err != nil {
		GetLogInstance().Error(err, "Unable to set init job controller reference")
		return err
	}
	err = r.Create(context.Background(), initJob)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create initial job ... maybe it already exists?")
		return err
	}
	r.InitJobCounter = DEFAULT_WAIT_INIT_JOB
	r.InitJob = initJob
	r.ContainerName = containerName

	return nil
}

// deployInitTasks will deploy initial job
// specified nodes in CRD
func (r *DeploymentReconciler) deployInitTasks(deployment *attestationv1alpha1.Deployment, req ctrl.Request) error {
	// Initial Job, the first thing
	err := r.createInitialJob(deployment, req)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create/read initial job")
		return err
	}
	if r.InitJobCounter > 0 {
		GetLogInstance().Info("Init job already exists ... (waiting for it)")
		return nil
	}

	err = r.createCAPasswordSecret(deployment, req)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create/read CA Password secret")
		return err
	}

	// remove, if possible, this declaration:
	nameSpace := req.NamespacedName.Namespace

	// Certificates Secret
	secretCerts, err := r.createCertsSecret(deployment, req)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create/read certs secret")
		return err
	}

	// Certificates TPM Secret
	secretTPMCerts, err := r.createTPMCertsSecret(deployment, req)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create/read TPM certs secret")
		return err
	}

	podList, err := PodList(nameSpace, context.Background(), r.InitJob.Name)
	if len(podList) == 0 {
		if err != nil {
			return err
		}
		return errors.New("Unable to parse pod associated to job " + r.InitJob.Name)
	}
	initJobPod := podList[0]

	GetLogInstance().Info("InitJob information", "Namespace", r.InitJob.Namespace,
		"Job Name", r.InitJob.Name, "Pod Name", initJobPod)

	// Once Initial Job is created, need to parse the certificates generated there (both keylime and tpm ones) only in case secrets are empty
	if secretCerts != nil && len(secretCerts.StringData) == 0 {
		certMap := parseCertificatesFromPod(initJobPod, r.ContainerName, "/tmp/certs", nameSpace)
		secretCerts.StringData = make(map[string]string)
		for k, v := range certMap {
			secretCerts.StringData[k] = v
		}
		err = r.Update(context.Background(), secretCerts)
		if err != nil {
			GetLogInstance().Error(err, "Unable to update certificates secret")
			return err
		}
	}
	if secretTPMCerts != nil && len(secretTPMCerts.StringData) == 0 {
		certMap := parseCertificatesFromPod(initJobPod, r.ContainerName, "/var/lib/keylime/tpm_cert_store/", nameSpace)
		secretTPMCerts.StringData = make(map[string]string)
		for k, v := range certMap {
			secretTPMCerts.StringData[k] = v
		}
		err = r.Update(context.Background(), secretTPMCerts)
		if err != nil {
			GetLogInstance().Error(err, "Unable to update TPM certificates secret")
			return err
		}
	}
	return nil
}

// getTenantPod function returns pod specification for tenant
func (r *DeploymentReconciler) getTenantPod(cr *attestationv1alpha1.Deployment, req ctrl.Request,
	labels map[string]string) *corev1.PodTemplateSpec {
	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Command: getTenantPodCommands(),
					Image:   getTenantImageNameAndTag(cr),
					Name:    "keylime-tenant",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "certs",
							MountPath: "/var/lib/keylime/cv_ca/",
							ReadOnly:  true,
						},
						{
							Name:      "tpm-cert-store",
							MountPath: "/var/lib/keylime/tpm_cert_store",

							ReadOnly: true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "tpm-cert-store",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: getTPMCertsSecretName(req),
						},
					},
				},
				{
					Name: "certs",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: getCertsSecretName(req),
						},
					},
				},
			},
			RestartPolicy:    corev1.RestartPolicyAlways,
			ImagePullSecrets: []corev1.LocalObjectReference{},
		},
	}
}

// deployKeylimeNodes will deploy
// specified nodes in CRD
func (r *DeploymentReconciler) deployKeylimeNodes(deployment *attestationv1alpha1.Deployment, req ctrl.Request) error {
	// If InitJob is running, must wait for it
	if r.InitJobCounter > 0 {
		GetLogInstance().Info("Init job running ... (waiting for it)")
		return nil
	}
	nameSpace := req.NamespacedName.Namespace
	tenantName := req.NamespacedName.Name + "-tenant-deployment"
	labels := map[string]string{
		"app": req.NamespacedName.Name,
	}
	tenantDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nameSpace,
			Name:      tenantName,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &[]int32{1}[0], // TODO: set configurable
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *r.getTenantPod(deployment, req, labels),
		},
	}
	search := types.NamespacedName{
		Namespace: nameSpace,
		Name:      tenantName,
	}
	err := r.Get(context.Background(), search, tenantDeployment)
	if err == nil {
		GetLogInstance().Info("Tenant is already there", "Namespace", nameSpace,
			"Name", tenantName)
		return nil
	}
	// Deploy Tenant
	GetLogInstance().Info("Creating Tenant Deployment")
	err = ctrl.SetControllerReference(deployment, tenantDeployment, r.Scheme)
	if err != nil {
		GetLogInstance().Error(err, "Unable to set tenant deployment controller reference")
		return err
	}
	err = r.Create(context.Background(), tenantDeployment)
	if err != nil {
		GetLogInstance().Error(err, "Unable to create tenant")
		return err
	}
	return nil
}

// getTenantImageNameAndTag will return image path and tag according to CRD
func getTenantImageNameAndTag(deployment *attestationv1alpha1.Deployment) string {
	path := deployment.Spec.NodeInfo.TenantImageInfo.ImageRepositoryPath
	if path == "" {
		GetLogInstance().Info("Did not find image path, using default one")
		path = "quay.io/keylime/keylime_tenant"
	}
	tag := deployment.Spec.NodeInfo.TenantImageInfo.ImageTag
	if tag == "" {
		GetLogInstance().Info("Did not find image tag, using default one")
		tag = "latest"
	}
	imagePathTag := path + ":" + tag
	GetLogInstance().Info("Tenant Information", "Path", path, "Tag", tag, "Complete Name", imagePathTag)
	return imagePathTag
}

// getInitJobImageNameAndTag will return image path and tag according to CRD
func getInitJobImageNameAndTag(deployment *attestationv1alpha1.Deployment) string {
	path := deployment.Spec.InitGlobal.InitialImage.ImageRepositoryPath
	if path == "" {
		GetLogInstance().Info("Did not find image path, using default one")
		path = "quay.io/keylime/keylime_tenant"
	}
	tag := deployment.Spec.InitGlobal.InitialImage.ImageTag
	if tag == "" {
		GetLogInstance().Info("Did not find image tag, using default one")
		tag = "latest"
	}
	imagePathTag := path + ":" + tag
	GetLogInstance().Info("Init Job Information", "Path", path, "Tag", tag, "Complete Name", imagePathTag)
	return imagePathTag
}

// getInitJobCommands will return array of commands to execute at init job
func getInitJobCommands() []string {
	commands := make([]string, 3)
	commands[0] = "/bin/bash"
	commands[1] = "-c"
	commands[2] = `
        # generate the CV CA
        mkdir -p /tmp/certs
        cd /tmp
        keylime_ca -d /tmp/certs --command init && keylime_ca -d /tmp/certs --command create --name server && keylime_ca -d /tmp/certs --command create --name client
        if [[ $? -ne 0 ]]
        then
          echo "ERROR: unable to generate certificates"
          exit 1
        fi
        # TODO: set next sleep configurable
        echo "GREAT: certificates generated! Will wait for a while until certs are parsed and stored in the certs secret (sleeping 40 secs)"
        sleep 40
        exit 0
`
	return commands
}

// getTenantPodCommands will return array of commands to execute in tenant
func getTenantPodCommands() []string {
	commands := make([]string, 3)
	commands[0] = "/bin/bash"
	commands[1] = "-c"
	commands[2] = `
            function on_exit() {
              echo "Exiting..."
              exit 0
            }
            trap on_exit EXIT
            echo "NOTE: This is not a service, but a simple exec-style Kubernetes pod. Access this pod through 'kubectl exec' and/or the 'keylime_tenant' script from the attestation operator repository (https://github.com/keylime/attestation-operator)."
            while true; do sleep 30; done
`
	return commands
}

// getInitJobEnvVars will return array of commands to execute at init job
func getInitJobEnvVars(req ctrl.Request) []corev1.EnvVar {
	init_job_env_vars := make([]corev1.EnvVar, 2)
	init_job_env_vars[0] = corev1.EnvVar{
		Name:  "KEYLIME_CA_PASSWORD",
		Value: "PENDING-HOW-TO-READ-THIS-FROM-SECRET:hhkl-keylime-ca-password",
	}
	init_job_env_vars[1] = corev1.EnvVar{
		Name:  "KEYLIME_SECRETS_CA_PW_NAME",
		Value: getCAPasswordSecretName(req),
	}
	return init_job_env_vars
}
