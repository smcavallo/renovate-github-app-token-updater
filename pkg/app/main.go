package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Main function
func main() {
	// Get the new token from GitHub
	logrus.Infof("Starting main function.")
	appId := os.Getenv("GITHUB_APP_ID")
	installationID := os.Getenv("GITHUB_INSTALLATION_ID")
	pemPath := "/tmp/private-key.pem"
	logrus.Infof("Refreshing token for app %s and installation %s", appId, installationID)
	jwt, jwtErr := GenerateJWT(appId, pemPath)
	if jwtErr != nil {
		logrus.Errorf("Error generating jwt: %v", jwtErr)
		os.Exit(1)
	}
	token, tokenErr := GetGithubAppInstallationToken(jwt, installationID)
	if tokenErr != nil {
		logrus.Errorf("Error generating github app token: %v", tokenErr)
		os.Exit(1)
	}
	// Update the kubernetes secret
	logrus.Infof("Updating kubernetes secret with new token")
	namespace := os.Getenv("SECRET_NAMESPACE")
	secretName := os.Getenv("SECRET_NAME")
	secretKey := os.Getenv("SECRET_KEY")
	UpdateKubernetesSecret(namespace, secretName, secretKey, token)
	logrus.Infof("Ending main function.")
}
