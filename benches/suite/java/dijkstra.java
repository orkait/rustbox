import java.util.*;
import java.io.*;

public class Solution {
    static class Edge {
        int to, weight;
        Edge(int to, int weight) {
            this.to = to;
            this.weight = weight;
        }
    }

    static class Node implements Comparable<Node> {
        int u;
        long d;
        Node(int u, long d) {
            this.u = u;
            this.d = d;
        }
        public int compareTo(Node other) {
            return Long.compare(this.d, other.d);
        }
    }

    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String line = br.readLine();
        if (line == null) return;
        StringTokenizer st = new StringTokenizer(line);
        int n = Integer.parseInt(st.nextToken());
        int targetM = Integer.parseInt(st.nextToken());
        int seed = Integer.parseInt(st.nextToken());
        int numQ = Integer.parseInt(st.nextToken());

        Random rng = new Random(seed);
        List<List<Edge>> adj = new ArrayList<>(n);
        for (int i = 0; i < n; i++) adj.add(new ArrayList<>());

        for (int i = 0; i < n - 1; i++) {
            int w = rng.nextInt(100) + 1;
            adj.get(i).add(new Edge(i + 1, w));
            adj.get(i + 1).add(new Edge(i, w));
        }

        int added = n - 1;
        while (added < targetM) {
            int u = rng.nextInt(n - 1);
            int v = rng.nextInt(Math.min(u + 50, n - 1) - (u + 1) + 1) + (u + 1);
            int w = rng.nextInt(100) + 1;
            adj.get(u).add(new Edge(v, w));
            adj.get(v).add(new Edge(u, w));
            added++;
        }

        long[] dist = new long[n];
        Arrays.fill(dist, Long.MAX_VALUE);
        dist[0] = 0;
        PriorityQueue<Node> pq = new PriorityQueue<>();
        pq.add(new Node(0, 0));

        while (!pq.isEmpty()) {
            Node curr = pq.poll();
            if (curr.d > dist[curr.u]) continue;
            for (Edge e : adj.get(curr.u)) {
                if (dist[curr.u] + e.weight < dist[e.to]) {
                    dist[e.to] = dist[curr.u] + e.weight;
                    pq.add(new Node(e.to, dist[e.to]));
                }
            }
        }

        rng = new Random(seed + 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numQ; i++) {
            int t = rng.nextInt(n - 1) + 1;
            if (dist[t] == Long.MAX_VALUE) {
                sb.append("-1\n");
            } else {
                sb.append(dist[t]).append("\n");
            }
        }
        System.out.print(sb.toString());
    }
}
