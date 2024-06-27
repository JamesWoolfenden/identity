package identity

type IAM struct {
	Name     string   `json:"Name"`
	IamType  string   `json:"IamType"`
	Policies []Policy `json:"Policies"`
}

type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// Statement is the core of an IAM policy.
type Statement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}
