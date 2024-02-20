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
	"bytes"
	"context"
	"fmt"
	"strings"

	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/remotecommand"
)

// podCommandExec uninterractively exec to the pod with the command specified.
// :param string command: command to execute
// :param string pod_name: Pod name
// :param string namespace: namespace of the Pod.
// :return: string: Output of the command. (STDOUT)
//
//	string: Errors. (STDERR)
//	 error: If any error has occurred otherwise `nil`
func podCommandExec(command, containerName, podName, namespace string) (string, string, error) {
	config, err := GetClusterClientConfig()
	if err != nil {
		return "", "", err
	}
	if config == nil {
		err = fmt.Errorf("nil config")
		return "", "", err
	}

	clientset, err := GetClientsetFromClusterConfig(config)
	if err != nil {
		return "", "", err
	}
	if clientset == nil {
		err = fmt.Errorf("nil clientset")
		return "", "", err
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")
	scheme := runtime.NewScheme()
	if err := core_v1.AddToScheme(scheme); err != nil {
		return "", "", fmt.Errorf("error adding to scheme: %v", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)
	req.VersionedParams(&core_v1.PodExecOptions{
		Command:   []string{"/bin/bash", "-c", command},
		Container: containerName,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, parameterCodec)

	exec, spdyerr := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if spdyerr != nil {
		return "", "", fmt.Errorf("error while creating Executor: %v, Command: %s", err, strings.Fields(command))
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return "", "", fmt.Errorf("error in Stream: %v, Command: %s", err, strings.Fields(command))
	}
	return stdout.String(), stderr.String(), nil
}
