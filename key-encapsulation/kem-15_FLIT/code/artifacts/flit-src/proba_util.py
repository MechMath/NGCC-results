from math import log, ceil

def build_ternary_law(n, num1, num_1):
    """ 字典表示三元分布的分布列
    :参数 n, num1, num_1: (integer)
    :return: 三元分布的分布列
    """
    D = {-1: num1/n,0: 0, 1: num_1/n}
    D[0] = 1 - D[1] - D[-1]
    return D

def mod_switch(x, q, rq):
    """ 模数转换
    :参数  x: (integer)
    :参数  q: (integer)
    :参数 rq: (integer)
    :return: x 从模数 q 的表示转换到模数 rq 的表示
    """
    return int(round(1.* rq * x / q) % rq)

def mod_centered(x, q):
    """ 中心化模运算
    :参数 x: (integer)
    :参数 q: (integer)
    :return: x 模 q 后的 [-q/2, q/2) 内的整数
    """
    a = x % q
    if a < q/2:
        return a
    return a - q

def build_mod_switching_error_law(q, rq):
    """ 构建模数转换引入的误差分布
    :参数  q: (integer)
    :参数 rq: (integer)
    :return: 误差分布
    """
    D = {}
    for x in range(q):
        y = mod_switch(x, q, rq)
        z = mod_switch(y, rq, q)
        d = mod_centered(x - z, q)
        D[d] = D.get(d, 0) + 1./q
    return D

def law_convolution(A, B):
    """ 两个离散概率分布（字典形式）的卷积运算
    :参数 A: (dictionnary)
    :参数 B: (dictionnary)
    :return: 两个独立随机变量之和的概率分布
    """
    C = {}
    for a in A:
        for b in B:
            c = a+b
            C[c] = C.get(c, 0) + A[a] * B[b]
    return C

def law_product(A, B):
    """ 两个离散概率分布（字典形式）的乘积分布
    :参数 A: (dictionary)
    :参数 B: (dictionary)
    :return: 两个独立随机变量之积的概率分布
    """
    C = {}
    for a in A:
        for b in B:
            c = a*b
            C[c] = C.get(c, 0) + A[a] * B[b]
    return C

def half_distribution(D):
    """将分布D的值若为偶数则减半，若为奇数则-1再减半
    :参数 D: (dictionary)
    :return 原分布的1/2
    """
    C = {}
    for a, prob in D.items():
        key = a // 2
        C[key] = C.get(key, 0) + prob
    return C

def clean_dist(A):
    """  清理概率分布
    :参数 A: (dictionnary)
    :return: 移除那些概率小于2^-300的项
    """
    B = {}
    for (x, y) in A.items():
        if y>2**(-300):
            B[x] = y
    return B

def iter_law_convolution(A, i):
    """ 输入分布 A 与自身进行 i 次卷积后的结果分布
    :从概率分布 D 中抽取的随机变量的绝对值严格大于 t 的概率 A: (dictionnary)
    :参数 i: (integer)
    :return: i 个独立同分布的随机变量之和的概率分布
    """
    D = {0: 1.0}
    i_bin = bin(i)[2:]  # binary representation of n
    for ch in i_bin:
        D = law_convolution(D, D)
        D = clean_dist(D)
        if ch == '1':
            D = law_convolution(D, A)
            D = clean_dist(D)
    return D

def tail_probability(D, t):
    """ 分布的尾部概率
    :参数 D: (Dictionnary)
    :参数 t: (integer)
    :return: 从概率分布 D 中抽取的随机变量的绝对值严格大于 t 的概率
    """
    s = 0
    ma = max(D.keys())
    if t >= ma:
        return 0
    for i in reversed(range(int(ceil(t)), ma)):  # 反向遍历求和
        s += D.get(i, 0) + D.get(-i, 0)
    return s

def convert_center_mod_distribution(D, q):
    """ 计算分布 D 中心化模 q 后的新分布
    :参数 D: (dictionnary)
    :参数 q: (integer)
    :return: 中心化模 q 后的新分布
    """
    new_D = {}
    for i, prob in D.items():
        i_mod = mod_centered(i, q)
        new_D[i_mod] = new_D.get(i_mod, 0) + prob
    return new_D

def abs_distribution(D):
    """ 将分布 D 转换为绝对值的分布。
    :参数 D:  (dictonarry)
    :return:  原分布的绝对值的分布
    """
    D_abs = {}
    for i, prob in D.items():
        abs_i = abs(i)
        D_abs[abs_i] = D_abs.get(abs_i, 0) + prob
    return D_abs 