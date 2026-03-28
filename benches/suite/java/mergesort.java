import java.util.Scanner;
import java.util.Random;
import java.util.Arrays;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        int n = sc.nextInt();
        int seed = sc.nextInt();
        
        Random random = new Random(seed);
        int[] arr = new int[n];
        for (int i = 0; i < n; i++) {
            arr[i] = random.nextInt(n + 1);
        }
        
        Arrays.sort(arr);
        
        int limit = Math.min(n, 5);
        for (int i = 0; i < limit; i++) {
            System.out.print(arr[i] + (i == limit - 1 ? "" : " "));
        }
        System.out.println();
        
        for (int i = 0; i < limit; i++) {
            System.out.print(arr[n - limit + i] + (i == limit - 1 ? "" : " "));
        }
        System.out.println();
    }
}
