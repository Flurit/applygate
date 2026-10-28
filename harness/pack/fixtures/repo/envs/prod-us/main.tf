terraform {
  backend "s3" {
    bucket = "acme-tf-state-prod"
    key    = "prod-us/terraform.tfstate"
    region = "us-east-1"
  }
}
