# non-prod/** is a standard environment in .seatbelt.yaml. The "prod" name
# hint must not fire on "non-prod" (agent-driven trial, 2026-10-29).
resource "aws_db_instance" "qa" {
  identifier = "qa-db"
}
