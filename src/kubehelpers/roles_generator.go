package kubehelpers

import "fmt"

func GenerateRole(namespace, roleName string) string {

	role := fmt.Sprintf(`
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: %s
  name: %s
rules:
- apiGroups: [""]
  resources: ["deployments", "pods"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

`, namespace, roleName)

	return role

}

func GenerateRoleBinding(namespace, roleBindingName, userName, roleName string) string {
	roleBinding := fmt.Sprintf(`
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: %s
  namespace: %s
subjects:
  - kind: User
    name: %s
    apiGroup: ""
roleRef:
  kind: Role
  name: %s
  apiGroup: ""
`, roleBindingName, namespace, userName, roleName)

	return roleBinding

}
