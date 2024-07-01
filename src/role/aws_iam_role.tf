resource "aws_iam_role" "identity" {
  name = "identity"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/basic"
        }
      },
    ]
  })

}

data "aws_caller_identity" "current" {}

output "role" {
  value = aws_iam_role.identity.arn
}