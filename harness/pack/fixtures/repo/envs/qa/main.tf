terraform {
  backend "s3" {
    bucket         = "acme-tf-state-staging"
    key            = "qa/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tf-locks"
  }
}

resource "aws_db_instance" "main" {
  identifier          = "qa-db"
  deletion_protection = true
}
