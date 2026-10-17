# vhs (https://github.com/charmbracelet/vhs) plus curl, so the recording can
# run the real installer, and gifsicle to shrink the GIF.
FROM ghcr.io/charmbracelet/vhs:v0.12.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gifsicle \
 && rm -rf /var/lib/apt/lists/*
