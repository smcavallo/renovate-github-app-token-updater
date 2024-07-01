package main

import (
	"context"
	b64 "encoding/base64"
	"fmt"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

func UpdateKubernetesSecret(namespace string, secretName string, secretKey string, tokenValue string) {
	// https://github.com/kubernetes/client-go/blob/master/examples/in-cluster-client-configuration/main.go
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// Encode the new token
	base64EncodedSecret := b64.StdEncoding.EncodeToString([]byte(tokenValue))

	// Attempt to patch current secret
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Update secret value
		_, updateErr := clientset.CoreV1().Secrets(namespace).Patch(context.TODO(), secretName, types.StrategicMergePatchType, []byte(`{"data": {"`+secretKey+`": "`+base64EncodedSecret+`"}}`), metav1.PatchOptions{FieldManager: "github-app-token-updater"})
		return updateErr
	})
	if retryErr != nil {
		logrus.Errorf("failed to update secret %s in namespace %s: %v", secretName, namespace, retryErr)
		panic(fmt.Errorf("update failed: %v", retryErr))
	}
	logrus.Infof("Updated kubernetes secret %s data key %s in namespace %s with new github app token", secretName, secretKey, namespace)
}
