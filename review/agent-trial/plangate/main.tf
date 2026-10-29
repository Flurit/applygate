# Plan-gate exercise stack (review/agent-trial/README.md, "Plan-gate exercise").
#
# Deliberately small: one stateful resource the plan gate's AWS rules know
# (aws_s3_bucket), its versioning (a protection rule), a security group (an
# exposure rule) and a DynamoDB table (also stateful). Every variable has a
# safe default; run-plangate.sh flips them one at a time to produce plans
# that should ask or block.
#
# The provider is pinned to LocalStack: hard-coded dummy keys and an endpoints
# block, so this stack cannot reach AWS even if real credentials were in the
# environment. Keep it that way.
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
  }
  backend "local" {}
}

variable "endpoint" {
  description = "LocalStack endpoint; the only place this stack talks to"
  type        = string
  default     = "http://localstack:4566"
}

variable "versioning" {
  description = "Bucket versioning status: Enabled (default) or Suspended"
  type        = string
  default     = "Enabled"
}

variable "force_destroy" {
  description = "aws_s3_bucket.force_destroy (default false)"
  type        = bool
  default     = false
}

variable "ingress_port" {
  description = "Port open to the internet on the security group (default 443)"
  type        = number
  default     = 443
}

provider "aws" {
  region     = "us-east-1"
  access_key = "test"
  secret_key = "test"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    s3       = var.endpoint
    ec2      = var.endpoint
    dynamodb = var.endpoint
    sts      = var.endpoint
    iam      = var.endpoint
  }
}

locals {
  name = "sb-trial-${terraform.workspace}"
}

resource "aws_s3_bucket" "data" {
  bucket        = "${local.name}-data"
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = var.versioning
  }
}

resource "aws_dynamodb_table" "sessions" {
  name         = "${local.name}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.42.0.0/16"
  tags       = { Name = local.name }
}

resource "aws_security_group" "web" {
  name        = "${local.name}-web"
  description = "trial web security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "from the internet"
    from_port   = var.ingress_port
    to_port     = var.ingress_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
