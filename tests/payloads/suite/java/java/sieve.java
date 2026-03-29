import java.util.Scanner;
import java.util.Arrays;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        int n = sc.nextInt();
        
        if (n < 2) {
            System.out.println(0);
            return;
        }

        byte[] s = new byte[n + 1];
        Arrays.fill(s, (byte) 1);
        s[0] = 0;
        s[1] = 0;

        int limit = (int) Math.sqrt(n);
        for (int i = 2; i <= limit; i++) {
            if (s[i] == 1) {
                for (int j = i * i; j <= n; j += i) {
                    s[j] = 0;
                }
            }
        }

        long count = 0;
        for (int i = 0; i <= n; i++) {
            if (s[i] == 1) {
                count++;
            }
        }
        System.out.println(count);
    }
}
