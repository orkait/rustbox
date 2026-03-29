import java.util.Scanner;

public class Solution {
    private static int n;
    private static int count = 0;
    private static boolean[] cols;
    private static boolean[] d1;
    private static boolean[] d2;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        if (sc.hasNextInt()) {
            n = sc.nextInt();
            cols = new boolean[n];
            d1 = new boolean[2 * n];
            d2 = new boolean[2 * n];
            bt(0);
            System.out.println(count);
        }
        sc.close();
    }

    private static void bt(int row) {
        if (row == n) {
            count++;
            return;
        }
        for (int col = 0; col < n; col++) {
            int idx1 = row - col + n;
            int idx2 = row + col;
            if (!cols[col] && !d1[idx1] && !d2[idx2]) {
                cols[col] = true;
                d1[idx1] = true;
                d2[idx2] = true;
                
                bt(row + 1);
                
                cols[col] = false;
                d1[idx1] = false;
                d2[idx2] = false;
            }
        }
    }
}
