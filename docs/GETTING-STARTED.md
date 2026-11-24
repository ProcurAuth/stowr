# Getting started

This guide takes about five minutes. You start a small S3-compatible service on your machine, put two files in it, and
open them in Stowr. Every command runs as written, on Linux.

You need these things:

- A Linux machine with amd64 or arm64.
- Docker, only to run the demo storage. Stowr itself does not need Docker.
- `curl`, `tar` and `sha256sum`.

The demo service listens on `127.0.0.1`. Nothing outside your machine can reach it. The commands pull one public image.
They publish no image.

## 1. Start a local S3-compatible service

Run SeaweedFS. It has the S3 API on port 8333, and it has no key. Use it only for this test.

```sh
docker run -d --rm --name stowr-demo-s3 -p 127.0.0.1:8333:8333 \
  chrislusf/seaweedfs:4.41 server -s3 -dir=/data \
  -master.volumeSizeLimitMB=64 -volume.max=30 -volume.minFreeSpace=1GiB
```

Wait about ten seconds. Then make a bucket and put two objects in it. The `--retry` options give the service time to
make its first storage volume.

```sh
sleep 10
curl -s -X PUT http://127.0.0.1:8333/demo
printf '# Hello\n\nThis file is in the bucket demo.\n' | curl -s --retry 5 --retry-delay 2 --retry-all-errors \
  -X PUT -H 'Content-Type: text/markdown' --data-binary @- http://127.0.0.1:8333/demo/notes/hello.md
printf 'id,name\n1,Ada\n2,Grace\n' | curl -s --retry 5 --retry-delay 2 --retry-all-errors \
  -X PUT -H 'Content-Type: text/csv' --data-binary @- http://127.0.0.1:8333/demo/data/people.csv
```

## 2. Get Stowr

Download the archive for your architecture and the file `checksums.txt`. Check the archive, then unpack it. For arm64, use
the archive `stowr_0.3.1_linux_arm64.tar.gz`.

```sh
curl -fsSLO https://github.com/ProcurAuth/stowr/releases/download/v0.3.1/stowr_0.3.1_linux_amd64.tar.gz
curl -fsSLO https://github.com/ProcurAuth/stowr/releases/download/v0.3.1/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf stowr_0.3.1_linux_amd64.tar.gz
./stowr version
```

The archive has one file: the static binary `stowr`. To build it from the source, use the script `scripts/static.sh` in the
repository. [DEVELOPMENT.md](DEVELOPMENT.md) tells how.

## 3. Write the configuration

Stowr reads one HCL file. It reads nothing else: no environment variable and no other file, unless the file names it.
Write `config.hcl`:

```hcl
access {
  mode = "open"
}

server {
  listen = "127.0.0.1:8080"
}

auth "local" {
  provider = "s3"
  mode     = "anonymous"
  endpoint = "http://127.0.0.1:8333"
  region   = "us-east-1"
}

bucket "demo" {
  name        = "Demo"
  auth        = "local"
  bucket      = "demo"
  permissions = ["read", "write", "delete"]
}
```

- `access` is mandatory. The mode `open` makes no check of the person. Use it only on your own machine, or behind a
  reverse proxy that signs users in. [ACCESS.md](ACCESS.md) tells about the mode `authzen`.
- `server.listen` binds the server to `127.0.0.1`, so only your machine can reach it.
- `auth` holds the endpoint and the credentials. This demo service has no key, so the mode is `anonymous`.
- `bucket` shows one bucket of the provider. `permissions` is a ceiling: Stowr never goes above it.

## 4. Check the file and start

Make Stowr check the file and print the value of each key. A mistake stops the command, and the message names the key.

```sh
./stowr print-config -c config.hcl
./stowr -c config.hcl
```

Stowr writes the values at start, then one line for each request. It also writes a warning: the mode `open` checks nobody.
Open `http://127.0.0.1:8080/` in a browser. Check the server from another terminal:

```sh
./stowr healthcheck
```

The command exits with 0 when the server answers.

## 5. Look around

1. Open the folder `notes`, then click `hello.md`. The page shows the rendered Markdown.
2. Go back and open `data/people.csv`. The page shows a table. Stowr reads only the bytes that it shows.
3. Click **Upload** and choose a file. A panel shows the progress. Stowr sends a large file in parts.
4. Open the menu at the top of the page. It shows each bucket, with icons for what you may do.

## 6. Remove the demo

Press Ctrl+C in the terminal of Stowr. Then remove the demo service. It had no volume, so Docker deletes its data.

```sh
docker stop stowr-demo-s3
rm -f stowr stowr_0.3.1_linux_amd64.tar.gz checksums.txt config.hcl
```

## Next steps

- Add the keys of a real provider. Use `access_key_id` and a secret from `_env` or `_file`. A secret in clear text in the
  file stops the start. [CONFIGURATION.md](CONFIGURATION.md) has an example for S3, Garage, SeaweedFS and GCS.
- Show a folder of the server as a bucket with a `volume` block.
- Check each person with the mode `authzen`: [ACCESS.md](ACCESS.md).
- Run Stowr as a service: [OPERATIONS.md](OPERATIONS.md).
- Read the list of all keys: [configuration-reference.md](configuration-reference.md).
