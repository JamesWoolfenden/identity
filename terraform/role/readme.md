# info

```text
aws sts assume-role --role-arn arn:aws:iam::680235478471:role/assume_role \
--profile basic --role-session-name temp

"AccessKeyId": "",
"SecretAccessKey": "",
"SessionToken": "",

export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_SESSION_TOKEN=""

export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""

[profile assumed]
role_arn = arn:aws:iam::680235478471:role/assume_role
source_profile = basic
```

```text
aws s3 ls --profile assumed

2022-07-25 23:09:13 680235478471-terraform-state
2024-05-28 14:08:10 amazon-datazone-680235478471-eu-west-2-237434990
2024-01-19 11:10:38 elasticbeanstalk-us-west-2-680235478471
2022-08-08 08:18:36 pike-680235478471
2021-05-20 11:12:45 trails-680235478471
```
