import java.util.Scanner;
import java.util.Random;
import java.util.StringJoiner;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        
        int n = sc.nextInt();
        int q = sc.nextInt();
        int seed = sc.nextInt();
        
        Random rand1 = new Random(seed);
        int[] arr = new int[n];
        long[] prefix = new long[n + 1];
        
        for (int i = 0; i < n; i++) {
            arr[i] = rand1.nextInt(1000) + 1;
            prefix[i + 1] = prefix[i] + arr[i];
        }
        
        Random rand2 = new Random(seed + 1);
        StringJoiner out = new StringJoiner("\n");
        
        for (int i = 0; i < q; i++) {
            int l = rand2.nextInt(n);
            int maxR = Math.min(l + 1000, n - 1);
            int r = rand2.nextInt(maxR - l + 1) + l;
            
            long sum = prefix[r + 1] - prefix[l];
            out.add(String.valueOf(sum));
        }
        
        System.out.println(out.toString());
    }
}
