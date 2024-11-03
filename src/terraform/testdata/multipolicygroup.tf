resource "aws_iam_group" "multipolicygroup" {
  name = "multipolicygroup"
  path = "/users/"
}

resource "aws_iam_group_policy" "multipolicygroupa" {
  name  = "policya"
  group = aws_iam_group.multipolicygroup.name

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version : "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:ListBucket"],
        Resource = "*",
    }, ]
  }, )
}

resource "aws_iam_group_policy" "multipolicygroupb" {
  name  = "policyb"
  group = aws_iam_group.multipolicygroup.name

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version : "2012-10-17",
    Statement = [
      {
        Effect   = "Deny",
        Action   = ["iam:*"],
        Resource = "*",
    }, ]
  }, )
}
