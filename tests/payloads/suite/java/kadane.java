import java.util.Scanner;
import java.util.Random;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        int n = sc.nextInt();
        int seed = sc.nextInt();
        
        Random random = new Random(seed);
        int[] arr = new int[n];
        for (int i = 0; i < n; i++) {
            arr[i] = random.nextInt(2001) - 1000;
        }
        
        long cur = arr[0];
        long mx = arr[0];
        
        for (int i = 1; i < n; i++) {
            int x = arr[i];
            cur = Math.max((long) x, cur + x);
            mx = Math.max(mx, cur);
        }
        
        System.out.println(mx);
    }
}
