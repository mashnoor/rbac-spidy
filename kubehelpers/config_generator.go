package kubehelpers

import (
	"gopkg.in/yaml.v3"
	"test/kubehelpers/models"
)

func GenerateKubeConfig(clusterName, userName, certificateAuthorityData, server, contextName, clientCertData, clientKeyData string) string {
	contextDetail := models.ContextDetail{
		Cluster: clusterName,
		User:    userName,
	}

	context := models.Context{
		Name:          contextName,
		ContextDetail: contextDetail,
	}

	clusterDetail := models.ClusterDetail{
		CertificateAuthorityData: certificateAuthorityData,
		Server:                   server,
	}

	cluster := models.Cluster{
		Name:          clusterName,
		ClusterDetail: clusterDetail,
	}

	userDetail := models.UserDetail{
		ClientCertificateData: clientCertData,
		ClientKeyData:         clientKeyData,
	}

	user := models.User{
		Name:       userName,
		UserDetail: userDetail,
	}

	config := models.Kubeconfig{
		ApiVersion:     "v1",
		Clusters:       []models.Cluster{cluster},
		Contexts:       []models.Context{context},
		CurrentContext: contextName,
		Kind:           "Config",
		Users:          []models.User{user},
	}

	out, err := yaml.Marshal(&config)

	if err != nil {
		panic(err)
	}

	return string(out)
}
