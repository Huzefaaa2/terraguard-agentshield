# Non-deploying demo fixture for AgentShield PR Guardian.
# Do not apply this Terraform. It intentionally shows risky patterns.

resource "aws_security_group_rule" "public_ssh_demo" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

data "aws_iam_policy_document" "wildcard_demo" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "example_storage" "unencrypted_demo" {
  encryption_enabled = false
  logging_enabled = false
}
