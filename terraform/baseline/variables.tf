variable "name_prefix" {
  type        = string
  description = "Stable resource name prefix for Acme Health baseline resources."
}

variable "suffix" {
  type        = string
  description = "Unique suffix shared with workload resources."
}

variable "evidence_vault_lock_mode" {
  type        = string
  description = "Default S3 Object Lock retention mode for evidence objects."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_vault_lock_mode)
    error_message = "Evidence vault lock mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "evidence_vault_retention_days" {
  type        = number
  description = "Default retention period, in days, for evidence objects."
  default     = 30

  validation {
    condition     = var.evidence_vault_retention_days >= 1
    error_message = "Evidence vault retention must be at least 1 day."
  }
}
