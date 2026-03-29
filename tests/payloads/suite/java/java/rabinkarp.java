import java.util.Scanner;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextInt()) return;
        int length = sc.nextInt();
        String pattern = sc.next();
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(pattern);
        }
        String text = sb.toString();
        
        long base = 31;
        long mod = 1_000_000_007L;
        int m = pattern.length();
        int n = text.length();
        
        long ph = 0;
        long th = 0;
        long power = 1;
        
        for (int i = 0; i < m; i++) {
            ph = (ph * base + (int) pattern.charAt(i)) % mod;
            th = (th * base + (int) text.charAt(i)) % mod;
            if (i > 0) {
                power = (power * base) % mod;
            }
        }
        
        int count = 0;
        for (int i = 0; i <= n - m; i++) {
            if (ph == th) {
                count++;
            }
            if (i + m < n) {
                long term1 = (th * base) % mod;
                long term2 = (((long) text.charAt(i) * power) % mod * base) % mod;
                th = (term1 - term2 + (int) text.charAt(i + m)) % mod;
                if (th < 0) {
                    th += mod;
                }
            }
        }
        System.out.println(count);
    }
}
