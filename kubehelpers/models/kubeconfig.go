package models

type Cluster struct {
	ClusterDetail ClusterDetail `yaml:"cluster"`
	Name          string        `yaml:"name"`
}
type ClusterDetail struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

type Context struct {
	ContextDetail ContextDetail `yaml:"context"`
	Name          string        `yaml:"name"`
}
type ContextDetail struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type UserDetail struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

type User struct {
	Name       string     `yaml:"name"`
	UserDetail UserDetail `yaml:"user"`
}

type Kubeconfig struct {
	ApiVersion     string    `yaml:"apiVersion"`
	Clusters       []Cluster `yaml:"clusters`
	Contexts       []Context `yaml:"contexts"`
	CurrentContext string    `yaml:"current-context"`
	Kind           string    `yaml:"kind"`
	Users          []User    `yaml:"users"`
}
