server {
  listen = ":8080"
}

# The access of humans (docs/ACCESS.md). The edge identifies the human and gives an identity token in the header
# X-Identity-Token. Stowr verifies the token on each request. It asks the PDP for each operation. The id of this
# service in the catalogue of the PDP is "stowr": it is the audience of the tokens.
access {
  mode = "authzen"

  identity {
    header           = "X-Identity-Token"
    issuer           = "issuer.example.invalid"
    audience         = "stowr"
    # The public key of the identity key of the issuer, in PEM. The cluster gives it as a secret file.
    public_keys_file = "/run/secrets/stowr_identity_keys"
    max_age          = "5m"
  }

  pdp {
    # The service of the PDP in the cluster. A network policy admits only the pods with a label to the port 4182.
    # No TLS inside the cluster.
    url             = "http://pdp.cluster.example.invalid:4182"
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
  endpoint               = "http://storage.cluster.example.invalid:8333"
  region                 = "us-east-1"
  access_key_id_file     = "/run/secrets/storage_s3_access_key"
  secret_access_key_file = "/run/secrets/storage_s3_secret_key"
}

bucket "registry" {
  name           = "registry"
  auth           = "seaweedfs"
  bucket         = "registry"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}

bucket "analytics" {
  name           = "analytics"
  auth           = "seaweedfs"
  bucket         = "analytics"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}

bucket "databases" {
  name           = "databases"
  auth           = "seaweedfs"
  bucket         = "databases"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}
