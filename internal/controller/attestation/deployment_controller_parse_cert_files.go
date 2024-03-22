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
	"strconv"
	"strings"
)

func getCertListFromPodStdout(stdout string) []string {
	// stdout is a string of the type:
	// a.pem\ncb.pem\nc.pem\n..z.pem\n
	return strings.Split(stdout, "\n")
}

func getCertContentsFromPod(podName, containerName, certDirectory, certFile, nameSpace string) string {
	// stdout is a string of the type:
	// a.pem\ncb.pem\nc.pem\n..z.pem\n
	command := "cat " + certDirectory + "/" + certFile
	stdout, _, err := podCommandExec(command, containerName, podName, nameSpace)
	if err != nil {
		GetLogInstance().Error(err, "Unable to execute command in pod",
			"command", command, "podName", podName, "containerName", containerName,
			"namespace", nameSpace)
		return ""
	}
	return stdout
}

func parseCertificatesFromPod(podName, containerName, certDirectory, nameSpace string) map[string]string {
	command := "ls -1 " + certDirectory
	// Connect to pod and read list of files
	stdout, _, err := podCommandExec(command, containerName, podName, nameSpace)
	if err != nil {
		GetLogInstance().Error(err, "Unable to execute command in pod",
			"command", command, "podName", podName, "containerName", containerName,
			"namespace", nameSpace)
		return nil
	}
	GetLogInstance().Info("Executed command in pod correctly", "stdout", stdout)
	certList := getCertListFromPodStdout(stdout)
	GetLogInstance().Info("Obtained a total of " + strconv.Itoa(len(certList)) + " certificates")
	certMap := make(map[string]string)
	var certContents string
	for _, cert := range certList {
		GetLogInstance().Info("Getting information for certificate [" + cert + "]")
		if len(cert) > 0 {
			certContents = getCertContentsFromPod(podName, containerName, certDirectory,
				cert, nameSpace)
			certMap[cert] = certContents
		}
	}
	return certMap
}
