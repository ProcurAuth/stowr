/* A file that sets each kind of key, and each form of a value. */
server {
  listen                              = "127.0.0.1:9090"
  job_history_limit                   = 20
  access_mode                         = "force_read_only"
  log_mode                            = "detailed"
  allow_full_object_fallback          = true
  memory_limit_bytes                  = 1073741824
  max_storage_bytes_per_request       = 1048576
  max_storage_requests_per_request    = 10000000
  max_range_cache_bytes               = 4294967296
  max_concurrent_storage_requests     = 1024
  max_concurrent_requests_per_storage = 256
  session_ttl_seconds                 = 604800
  max_stats_folders                   = 1000000
  max_archive_entries                 = 1
  max_background_storage_bytes        = 1125899906842624
  max_background_storage_requests     = 1
}

access {
  mode = "open"
}

auth "storage" {
  provider               = "s3"
  endpoint               = "https://[::1]:9000/base%20path"
  region                 = "eu-west-3"
  access_key_id_env      = "FIXTURE_ACCESS_KEY"
  secret_access_key_file = "secrets/s3-secret"
  session_token_env      = "FIXTURE_SESSION_TOKEN"
  insecure_skip_verify   = true

  usage {
    source         = "seaweedfs"
    endpoint       = "http://master.example.invalid:9333"
    filer_endpoint = "https://filer.example.invalid:8888"
  }
}

auth garage {
  provider              = "s3"
  mode                  = "access_key"
  endpoint              = "http://garage.example.invalid:3900"
  region                = "garage"
  access_key_id         = "GK0123"
  secret_access_key_env = "FIXTURE_GARAGE_SECRET"
  usage {
    source     = "garage"
    endpoint   = "http://garage.example.invalid:3903"
    token_file = "@DIR@/secrets/garage-token"
  }
}

auth "google" {
  provider         = "gcs"
  credentials_file = "./secrets/../secrets/gcs.json"
}

auth "public-gcs" {
  provider = "gcs"
  endpoint = "http://gcs.example.invalid:4443/storage"
}

bucket "documents" {
  name           = "Documents \"main\"\u00a0é\t日本"
  auth           = "storage"
  bucket         = "documents"
  permissions    = ["read", "write"]
  root_prefix    = "tenant/a/"
  max_scan_pages = 0
  encryption     = "sse-s3"
  quota_bytes    = 1152921504606846976
}

bucket "empty-permissions" {
  auth        = "garage"
  bucket      = "empty"
  permissions = []
  encryption  = ""
}

bucket "photos" {
  auth   = "google"
  bucket = "photos.example"
}

// A volume with a root prefix.
volume "files" {
  name           = "Files"
  path           = "@DIR@/volume"
  root_prefix    = "shared/"
  permissions    = ["read"]
  max_scan_pages = 1000000
}

volume "-" {
  path = "@DIR@/volume"
}
