package identity

import "fmt"

func FormatRole(user IAM) string {
	role := fmt.Sprintf("arn:aws:iam::%s:role/identity", user.Account)
	return role
}
