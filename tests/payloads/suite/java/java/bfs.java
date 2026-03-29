import java.util.*;
import java.io.*;

public class Solution {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String line = br.readLine();
        if (line == null) return;
        int n = Integer.parseInt(line.trim());
        
        List<List<Integer>> adj = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            adj.add(new ArrayList<>());
        }
        
        for (int i = 0; i < n - 1; i++) {
            adj.get(i).add(i + 1);
            adj.get(i + 1).add(i);
        }
        
        for (int i = 0; i <= n - 3; i += 2) {
            adj.get(i).add(i + 2);
            adj.get(i + 2).add(i);
        }
        
        int[] dist = new int[n];
        Arrays.fill(dist, -1);
        dist[0] = 0;
        
        Deque<Integer> q = new ArrayDeque<>();
        q.add(0);
        
        while (!q.isEmpty()) {
            int u = q.pollFirst();
            for (int v : adj.get(u)) {
                if (dist[v] == -1) {
                    dist[v] = dist[u] + 1;
                    q.add(v);
                }
            }
        }
        
        System.out.println(dist[n - 1]);
    }
}
