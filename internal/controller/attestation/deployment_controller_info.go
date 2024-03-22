/*
Copyright 2024.

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
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodList list the pods in a particular namespace
// :param string namespace: namespace of the Pod
// :param context: context of the controller
// :param startswith: string that indicates if pod names have to start with a certain string
//
// :return:
//
//	string: Output of the command. (STDOUT)
//	 error: If any error has occurred otherwise `nil`
func PodList(namespace string, ctx context.Context, startsWith string) ([]string, error) {
	config, err := GetClusterClientConfig()
	if err != nil {
		GetLogInstance().Info("Unable to get ClusterClientConfig")
		return nil, err
	}
	if config == nil {
		GetLogInstance().Info("Unable to get config")
		err = fmt.Errorf("nil config")
		return nil, err
	}

	clientset, err := GetClientsetFromClusterConfig(config)
	if err != nil {
		GetLogInstance().Info("Unable to get ClientSetFromClusterConfig")
		return nil, err
	}
	if clientset == nil {
		GetLogInstance().Info("Clientset is null")
		err = fmt.Errorf("nil clientset")
		return nil, err
	}

	pods, _ := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	lpods := make([]string, len(pods.Items))
	podIndex := 0
	for i, pod := range pods.Items {
		GetLogInstance().Info("Execution information (Pod)", "i", i, "Pod", pod.GetName(),
			"Pod Reason", pod.Status.Reason, "Pod Status", pod.Status)
		if len(startsWith) == 0 || strings.HasPrefix(pod.GetName(), startsWith) {
			GetLogInstance().Info("Pod added to list", "PodName", pod.GetName())
			lpods[podIndex] = pod.GetName()
			podIndex += 1
		}
	}
	return lpods, nil
}
