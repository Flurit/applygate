TF ?= terraform

.PHONY: plan destroy fmt

plan:
	$(TF) plan -out=tfplan

fmt:
	$(TF) fmt -recursive

destroy:
	@echo "tearing down"
	$(TF) destroy -auto-approve
