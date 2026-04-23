# Environment Variables

| Variable Name | Description | Use |
|---------------|-------------|-----|
| VIRTCI_BACKEND_PORT | The port that the `virtci serve` command uses.<br><br>If `virtci serve --port N` is supplied, that takes precedence.<br>`VIRTCI_BACKEND_PORT` takes precedence over default port of 6399. | export VIRTCI_BACKEND_PORT=8080 |
| VIRTCI_S3_URLS | The s3 url(s) that the `virtci serve` backend can use.<br>Multiple can be supplied, using the space `' '` as separators. The first one is always prioritized for read operations, but write operations are done to all. If the first is unavailable, the new primary becomes the second, and continuing round-robin. | export VIRTCI_S3_URLS="localhost:3900"<br>export VIRTCI_S3_URLS="localhost:3900 localhost:4900" |
| VIRTCI_HOME_DIR | The directory where user specific virtci files are stored, such as user created or manually imported VMs (not pulled). | export VIRTCI_HOME_DIR="~/virtci/" |
| VIRTCI_CACHE_DIR | The directory where remotely pulled VMs from `virtci pull`, or pulled from a `virtci run` workflow are stored. | export VIRTCI_CACHE_DIR="/var/cache/virtci_images/" |
