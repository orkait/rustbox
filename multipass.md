# Multipass VM Setup for cgroup v1 Testing

Rustbox supports both cgroup v1 and v2. Modern kernels (6.x) ship with v2-only. To test cgroup v1 behavior (and to run Judge0 which requires v1), use a Multipass VM with an older kernel.

## Why Multipass?

Docker containers share the host kernel. If your host kernel doesn't have cgroup v1 compiled in, no container can use v1 either. A VM runs its own kernel.

Ubuntu 22.04 ships kernel 5.15 which has BOTH v1 and v2 compiled in but defaults to v2. We switch it to v1 via a boot parameter.

## Setup

```bash
# Install multipass
sudo snap install multipass

# Create VM: 4 cores, 4GB RAM, 20GB disk
multipass launch 22.04 --name judge-bench --cpus 4 --memory 4G --disk 20G

# Enable cgroup v1 (hybrid mode)
multipass exec judge-bench -- sudo bash -c '
    sed -i "s|GRUB_CMDLINE_LINUX_DEFAULT=\"\"|GRUB_CMDLINE_LINUX_DEFAULT=\"systemd.unified_cgroup_hierarchy=0\"|" /etc/default/grub
    update-grub
'

# Reboot to apply
multipass stop judge-bench
multipass start judge-bench

# Verify cgroup v1 is active
multipass exec judge-bench -- ls /sys/fs/cgroup/memory/memory.limit_in_bytes
# Should print the path - means v1 memory controller is mounted
```

## Install Docker inside VM

```bash
multipass exec judge-bench -- sudo bash -c '
    apt-get update -qq
    apt-get install -y -qq docker.io docker-compose-v2 curl python3 jq
    systemctl start docker
'
```

## Mount host project into VM

```bash
multipass mount /path/to/rustbox judge-bench:/mnt/rustbox
```

## Build and run Rustbox in VM

```bash
# Build image
multipass exec judge-bench -- sudo bash -c 'cd /mnt/rustbox && docker build -t rustbox:bench .'

# Run with strict mode (4 cores, 2GB limit)
multipass exec judge-bench -- sudo docker run -d --name rustbox-bench -p 4096:4096 \
    --cpus=4 --memory=2g \
    --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
    --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -e RUSTBOX_WORKERS=2 \
    rustbox:bench

# Verify
multipass exec judge-bench -- curl -s http://localhost:4096/api/health | python3 -m json.tool
```

## Run Judge0 in VM (requires cgroup v1)

```bash
# Create config
multipass exec judge-bench -- bash -c '
cat > ~/judge0.conf << EOF
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=benchpass
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=judge0
POSTGRES_USER=judge0
POSTGRES_PASSWORD=benchpass
ENABLE_WAIT_RESULT=true
NUMBER_OF_RUNS=2
EOF
'

# Create compose file
multipass exec judge-bench -- bash -c '
cat > ~/judge0-bench.yml << EOF
services:
  server:
    image: judge0/judge0:latest
    volumes:
      - ./judge0.conf:/judge0.conf:ro
    ports:
      - "2358:2358"
    privileged: true
    depends_on: [db, redis]
  worker:
    image: judge0/judge0:latest
    command: ["./scripts/workers"]
    volumes:
      - ./judge0.conf:/judge0.conf:ro
    privileged: true
    depends_on: [db, redis]
  db:
    image: postgres:16.2
    env_file: judge0.conf
  redis:
    image: redis:7.2.4
    command: ["bash", "-c", "docker-entrypoint.sh --appendonly no --requirepass benchpass"]
EOF
'

# Start
multipass exec judge-bench -- sudo docker compose -f /home/ubuntu/judge0-bench.yml --project-directory /home/ubuntu up -d
```

## Cleanup

```bash
multipass stop judge-bench
multipass delete judge-bench
multipass purge
```

## Notes

- Judge0 latest (1.13.1) uses IOI Isolate 1.8.1 which does NOT support cgroup v2
- IOI Isolate itself supports v2 since v2.1, but Judge0 hasn't updated
- Judge0 GitHub issue #543 tracks this
- Rustbox auto-detects v1/v2 and works on both
