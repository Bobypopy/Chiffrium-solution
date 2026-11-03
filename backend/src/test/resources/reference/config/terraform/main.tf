resource "tls_private_key" "ci" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
