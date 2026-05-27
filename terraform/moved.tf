moved {
  from = aws_kms_key.phi
  to   = module.grc_baseline.aws_kms_key.phi
}

moved {
  from = aws_kms_alias.phi
  to   = module.grc_baseline.aws_kms_alias.phi
}
