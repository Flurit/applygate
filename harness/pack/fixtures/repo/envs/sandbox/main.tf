terraform {
  backend "local" {}
}

resource "terraform_data" "scratch" {
  input = "dev"
}
