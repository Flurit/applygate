terraform {
  backend "s3" {
    bucket         = "acme-tf-state-prod"
    key            = "prod-eu/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tf-locks"
  }
}

resource "aws_db_instance" "main" {
  identifier          = "prod-eu-db"
  deletion_protection = true
}
