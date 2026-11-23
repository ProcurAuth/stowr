server {
  listen = ":8080"
}

# The access of humans (docs/ACCESS.md). The edge identifies the human and gives an identity token in the header
# X-Identity-Token. Stowr verifies the token on each request. It asks the PDP for each operation. The id of this
# service in the catalogue of the PDP is "infra-s3": it is the audience of the tokens.
access {
  mode = "authzen"

  identity {
    header           = "X-Identity-Token"
    issuer           = "issuer.example.invalid"
    audience         = "infra-s3"
    # The public key of the identity key of the issuer, in PEM. The deployment gives it as a secret file.
    public_keys_file = "/run/secrets/stowr_identity_keys"
    max_age          = "5m"
  }

  pdp {
    # The PDP answers on its port 4182. The network has no TLS: only the containers of the stack join it.
    url             = "http://pdp.example.invalid:4182"
    plain_http      = true
    token_file      = "/run/secrets/stowr_pdp_token"
    timeout         = "500ms"
    cache_ttl       = "30s"
    max_evaluations = 64
  }
}

auth "seaweedfs" {
  provider               = "s3"
  mode                   = "access_key"
  endpoint               = "http://storage.example.invalid:8333"
  region                 = "home"
  access_key_id_file     = "/run/secrets/storage_s3_access_key"
  secret_access_key_file = "/run/secrets/storage_s3_secret_key"
}

bucket "docker-registry" {
  name           = "docker-registry"
  auth           = "seaweedfs"
  bucket         = "docker-registry"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}

bucket "clickhouse-system" {
  name           = "clickhouse-system"
  auth           = "seaweedfs"
  bucket         = "clickhouse-system"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}
