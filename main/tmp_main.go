package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"test/kubehelpers/models"
)

func main() {
	contextDetail := models.ContextDetail{
		Cluster: "name",
		User:    "user",
	}

	context := models.Context{
		Name:          "context_name",
		ContextDetail: contextDetail,
	}

	clusterDetail := models.ClusterDetail{
		CertificateAuthorityData: "ABCD",
		Server:                   "https://192.168.10.112:6443",
	}

	cluster := models.Cluster{
		Name:          "cluster name",
		ClusterDetail: clusterDetail,
	}

	userdetail := models.UserDetail{
		ClientCertificateData: "client-cert-data",
		ClientKeyData:         "client key data",
	}

	user := models.User{
		Name:       "mash",
		UserDetail: userdetail,
	}

	config := models.Kubeconfig{
		ApiVersion:     "v1",
		Clusters:       []models.Cluster{cluster},
		Contexts:       []models.Context{context},
		CurrentContext: "current-context",
		Kind:           "config",
		Users:          []models.User{user},
	}

	out, err := yaml.Marshal(&config)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))

}
