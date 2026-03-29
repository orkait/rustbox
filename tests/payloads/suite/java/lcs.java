import java.util.Scanner;

public class Solution {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (!sc.hasNextLine()) return;
        String a = sc.nextLine().trim();
        if (!sc.hasNextLine()) return;
        String b = sc.nextLine().trim();
        
        int n = a.length();
        int m = b.length();
        
        int[] prev = new int[m + 1];
        
        for (int i = 1; i <= n; i++) {
            int[] cur = new int[m + 1];
            char charA = a.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                if (charA == b.charAt(j - 1)) {
                    cur[j] = prev[j - 1] + 1;
                } else {
                    int val1 = prev[j];
                    int val2 = cur[j - 1];
                    cur[j] = (val1 > val2) ? val1 : val2;
                }
            }
            prev = cur;
        }
        
        System.out.println(prev[m]);
    }
}
