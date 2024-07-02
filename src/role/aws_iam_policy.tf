data "aws_iam_policy_document" "policy" {
  statement {
    effect = "Allow"
    actions = [
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListGroupPolicies",
      "iam:ListAttachedGroupPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetUserPolicy",
      "iam:GetRolePolicy",
      "iam:GetGroupPolicy",
      "iam:ListGroupsForUser"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "identity-minimum"
  description = "Permissions required ro run identity"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "role-attach" {
  role       = aws_iam_role.identity.name
  policy_arn = aws_iam_policy.policy.arn
}

# resource "aws_iam_user_policy_attachment" "user-attach" {
#   user       = "basic"
#   policy_arn = aws_iam_policy.policy.arn
# }