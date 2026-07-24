## Update to a new tag

From `libinjection-rs/`:

```bash
TAG=v0.3.2
DIR=libinjection-go-0.3.2

rm -f tests/corpus/test-*.txt

curl -L "https://github.com/corazawaf/libinjection-go/archive/refs/tags/${TAG}.tar.gz" | \
  tar xz --strip-components=2 -C tests/corpus "${DIR}/tests"

# Refresh the pin noted at the top of this file, then commit.