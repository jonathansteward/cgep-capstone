variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Reserved concurrency for the intake Lambda. -1 = unreserved. Accounts with the default limit of 10 cannot reserve any (AWS requires 10 unreserved); raise the quota, then set this."
  default     = -1
}

variable "api_throttle_burst" {
  type    = number
  default = 20
}

variable "api_throttle_rate" {
  type    = number
  default = 10
}

variable "evidence_lock_mode" {
  type        = string
  description = "Object Lock mode for the evidence vault. GOVERNANCE for the sandbox; COMPLIANCE is irreversible until retention expires."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_lock_mode)
    error_message = "evidence_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "evidence_retention_days" {
  type        = number
  description = "Default Object Lock retention for new evidence objects (governance mode; applies to objects written after a change)."
  default     = 30
}
