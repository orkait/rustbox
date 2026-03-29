import java.util.Scanner;
import java.util.Arrays;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        int n = sc.nextInt();
        
        int[] arr = new int[n];
        for (int i = 0; i < n; i++) {
            arr[i] = i * 2;
        }
        
        if (!sc.hasNextInt()) return;
        int q = sc.nextInt();
        
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < q; i++) {
            int target = sc.nextInt();
            int idx = Arrays.binarySearch(arr, target);
            
            if (idx >= 0) {
                out.append(idx).append("\n");
            } else {
                out.append("-1\n");
            }
        }
        System.out.print(out.toString());
    }
}
