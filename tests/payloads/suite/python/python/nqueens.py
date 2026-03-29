import sys
n = int(sys.stdin.readline())
count = 0
cols = [False]*n; d1 = [False]*(2*n); d2 = [False]*(2*n)
def bt(row):
    global count
    if row == n: count += 1; return
    for col in range(n):
        if not cols[col] and not d1[row-col+n] and not d2[row+col]:
            cols[col]=d1[row-col+n]=d2[row+col]=True
            bt(row+1)
            cols[col]=d1[row-col+n]=d2[row+col]=False
bt(0)
print(count)
