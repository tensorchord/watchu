# WatchU

Hey, Agent! :honeybee: The bees are watching you! :honeybee:

## Usage

- build

```bash
make build

# with debug
sudo ./bin/app -debug
# with TUI
sudo ./bin/app -tui
```

If you want to build the docker image and run it as a container:

```bash
docker buildx build -t watchu -f Dockerfile --load .
docker run --rm \
    --cap-add=CAP_SYS_ADMIN \
    --cap-add=CAP_SYS_PTRACE \
    --cap-add=CAP_BPF \
    --cap-add=CAP_PERFMON \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    --pid=host \
    --security-opt apparmor=unconfined \
    watchu
```
