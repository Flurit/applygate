terraform {
  backend "local" {}
}
resource "terraform_data" "app" {
  input = "v1"
}
