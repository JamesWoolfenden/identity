package Identity

import "fmt"

func FormatRole(user IAM) (role string) {
	return fmt.Sprintf("arn:aws:iam::%s:role/identity", user.Account)
}
