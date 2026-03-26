# Benchmark: Prime Sieve Stress Test

## Test workload

Sieve of Eratosthenes - finds all primes up to N. CPU-bound, allocates memory, produces deterministic output.

- Python: sieve(1,000,000) - expected output: `78498`
- C++: sieve(1,000,000) - compiled with g++ -O2, expected output: `78498`
- Java: sieve(1,000,000) - compiled with javac, expected output: `78498`

## Source code

### Python
```python
import math
def sieve(n):
    p = [True] * (n + 1)
    p[0] = p[1] = False
    for i in range(2, int(math.sqrt(n)) + 1):
        if p[i]:
            for j in range(i*i, n + 1, i):
                p[j] = False
    return sum(p)
print(sieve(1000000))
```

### C++
```cpp
#include <iostream>
#include <vector>
#include <cmath>
using namespace std;
int main() {
    int n = 1000000;
    vector<bool> sieve(n + 1, true);
    sieve[0] = sieve[1] = false;
    for (int i = 2; i <= sqrt(n); i++)
        if (sieve[i])
            for (int j = i*i; j <= n; j += i)
                sieve[j] = false;
    int count = 0;
    for (int i = 0; i <= n; i++) if (sieve[i]) count++;
    cout << count << endl;
}
```

### Java
```java
public class Main {
    public static void main(String[] args) {
        int n = 1000000;
        boolean[] sieve = new boolean[n + 1];
        java.util.Arrays.fill(sieve, true);
        sieve[0] = sieve[1] = false;
        for (int i = 2; i * i <= n; i++)
            if (sieve[i])
                for (int j = i * i; j <= n; j += i)
                    sieve[j] = false;
        int count = 0;
        for (int i = 0; i <= n; i++) if (sieve[i]) count++;
        System.out.println(count);
    }
}
```

## Results: Sequential (30 runs each)

Environment: Multipass VM, 4 cores, 4GB RAM, kernel 5.15, cgroup v1

| Language | Judge0 Avg | Judge0 RPS | Rustbox Avg | Rustbox RPS |
|----------|-----------|------------|-------------|-------------|
| Python sieve(1M) | **185ms** | **5.39** | 207ms | 4.83 |
| C++ sieve(1M) | 438ms | 2.28 | **415ms** | **2.40** |
| Java sieve(1M) | 1269ms | 0.79 | **596ms** | **1.68** |

Judge0 is faster for Python sequential (less per-request overhead).
Rustbox wins C++ (marginal) and Java (2x - less Ruby/Rails/Redis overhead).

## Results: Concurrent (Python sieve 1M, best of 3)

| Concurrency | Judge0 RPS | Rustbox RPS | Speedup |
|-------------|-----------|-------------|---------|
| x5 | 5.78 | **22.62** | 3.9x |
| x10 | 5.49 | **22.68** | 4.1x |
| x20 | 5.49 | **22.62** | 4.1x |

Judge0 plateaus at ~10 RPS regardless of concurrency (Rails/Redis bottleneck).
Rustbox scales with concurrency (axum/tokio async dispatch).

## Results: Local (host machine, no VM, degraded mode)

Environment: 16 cores, 29GB RAM, kernel 6.17, cgroup v2

| Concurrency | RPS | Success |
|-------------|-----|---------|
| x5 | 22.32 | 5/5 |
| x10 | 23.58 | 10/10 |
| x20 | 30.49 | 20/20 |
| x50 | 35.14 | 50/50 |
| x100 | 38.34 | 100/100 |

## Known issue: intermittent TLE under high concurrency in VM strict mode

At x50 concurrent in the VM (strict mode, cgroup v1), ~2% of requests occasionally get false TLE verdicts with cpu_time near zero. The sandbox setup (namespace creation, mount operations) sometimes blocks for seconds under kernel cgroup v1 contention in the VM.

Symptoms:
- verdict: TLE
- wall_time: ~22s (full kill_timeout)
- cpu_time: ~0ms (code never ran)
- error: "failed to decode json on fd: EOF" (proxy killed before reporting)
- signal: 9 (SIGKILL from supervisor)

Root cause: Under investigation. Likely kernel-level cgroup v1 lock contention during concurrent namespace + mount + cgroup operations in the VM. Does NOT reproduce on bare metal or with cgroup v2.

## How to run these benchmarks

### CLI (local, permissive)
```bash
cargo build --release
./target/release/judge execute-code --permissive --allow-degraded \
    --language python --code 'import math
def sieve(n):
    p=[True]*(n+1)
    p[0]=p[1]=False
    for i in range(2,int(math.sqrt(n))+1):
        if p[i]:
            for j in range(i*i,n+1,i): p[j]=False
    return sum(p)
print(sieve(1000000))'
```

### HTTP API (concurrent)
```bash
# Start judge-service
./target/release/judge-service &

# Create payload
python3 -c "
import json
py='import math\ndef sieve(n):\n    p=[True]*(n+1)\n    p[0]=p[1]=False\n    for i in range(2,int(math.sqrt(n))+1):\n        if p[i]:\n            for j in range(i*i,n+1,i): p[j]=False\n    return sum(p)\nprint(sieve(1000000))'
with open('/tmp/payload.json','w') as f: json.dump({'language':'python','code':py},f)
"

# Fire N concurrent
for i in $(seq 1 50); do
    curl -s -X POST "http://localhost:4096/api/submit?wait=true" \
        -H "Content-Type: application/json" \
        -d @/tmp/payload.json > /tmp/r_$i.json &
done
wait

# Count successes
ok=0
for i in $(seq 1 50); do
    v=$(python3 -c "import json; print(json.load(open('/tmp/r_$i.json'))['verdict'])" 2>/dev/null)
    [ "$v" = "AC" ] && ((ok++))
done
echo "$ok/50 OK"
```
