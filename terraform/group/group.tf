resource "aws_iam_group" "idgroup" {
  name               = "idgroup"
}

resource "aws_iam_group_policy" "idgroup" {
  name  = "my_developer_policy"
  group = aws_iam_group.idgroup.name

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "attached" {
  group      = aws_iam_group.idgroup.name
  policy_arn = aws_iam_policy.policy.arn
}

data "aws_iam_policy_document" "policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "assume-test-policy-forgroup"
  description = "A test policy"
  policy      = data.aws_iam_policy_document.policy.json
}