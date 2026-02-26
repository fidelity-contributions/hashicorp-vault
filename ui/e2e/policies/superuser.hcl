# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1

path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
// needed permissions to be able to seal vault
path "sys/seal" {
  capabilities = ["sudo", "update"]
}