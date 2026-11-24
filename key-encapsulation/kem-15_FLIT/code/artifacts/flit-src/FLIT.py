from proba_util import *

class FLITParameterSet:
    def __init__(self, n, f, g, r, e, q, m, rqc = None):
        self.n = n      #  多项式的次数 n （样本个数）
        self.f = f      #  采样 f' 的中心二项分布的参数
        self.g = g      #  采样 g  的中心二项分布的参数
        self.r = r      #  采样 r  的中心二项分布的参数
        self.e = e      #  采样 e  的分布的参数
        self.q = q      #  模数 q
        self.m = m      #  密钥长度 m
        self.rqc = rqc  #  压缩后的模数 
        
def FLIT_final_error_distribution(ps, chi_m=None):
    """ 计算 KEM 中最终解密失败的误差分布
    :参数 params: (KEMParameterSet)
    :参数 chi_m: m 的系数概率分布，默认为平均情况（随机消息）
    :return: KEM 中最终解密失败的误差分布
    """
    chi_f = build_ternary_law(ps.n, ps.f, ps.f)   # f 的系数概率分布
    chi_g = build_ternary_law(ps.n, ps.g, ps.g)   # g 的系数概率分布
    chi_r = build_ternary_law(ps.n, ps.r, ps.r)   # r 的系数概率分布
    chi_e = build_ternary_law(ps.n, ps.e, ps.e)   # e 的系数概率分布
    if chi_m is None:
        chi_m = build_ternary_law(ps.n, ps.n/2,  0)   # m 的系数概率分布（平均情况）
    
    if ps.rqc is not None:
        chi_moderror = build_mod_switching_error_law(ps.q, ps.rqc)  # 模数切换误差的系数概率分布
        chi_e = law_convolution(chi_e, chi_moderror)                # e + 模数切换误差 的系数概率分布
        
    chi_gs = iter_law_convolution(law_product(chi_g, chi_r), ps.n)  # g*r 系数概率分布
    chi_fe = iter_law_convolution(law_product(chi_f, chi_e), ps.n)  # f*e 的系数概率分布
    chi_gs_fe = law_convolution(chi_gs, chi_fe)                     # g*r + f*e 的系数概率分布
    
    chi_fm = iter_law_convolution(law_product(chi_f, chi_m), ps.n)  # f*m 的系数概率分布
    chi_half_fm = half_distribution(chi_fm)                         # ≈ f*m/2 的系数概率分布
    
    D = law_convolution(chi_gs_fe, chi_half_fm)                     # g*s + f*e + f*m/2 的系数概率分布
    
    return D

def FLIT_decryption_failure_probability(ps, chi_m=None):
    """ 计算 FLIT 中解密失败的概率
    :参数 params: (FLITParameterSet)
    :参数 chi_m: m 的系数概率分布，默认为平均情况（随机消息）
    :return: FLIT 中解密失败的概率
    """
    F = FLIT_final_error_distribution(ps, chi_m)
    F1 = convert_center_mod_distribution(F, ps.q)  # e' 系数中心模 q 后的概率分布
    F2 = abs_distribution(F1)  # 误差绝对值的分布
    F3 = iter_law_convolution(F2, int(ps.n/ps.m))
    
    proba1 = tail_probability(F3, int(ps.n/ps.m)*(ps.q-1)/4)   # 单一系数不成立的概率
    proba = ps.m * proba1                       # m个系数中至少一次不成立(利用了近似1-(1-p)^m = mp)
    return F3, proba    

if __name__ == "__main__":
    FLIT128 = FLITParameterSet(n = 512,  f = 64,  g = 160, r = 64,  e = 160, q = 769,  m = 256, rqc = 256)  
    FLIT256 = FLITParameterSet(n = 1024, f = 160, g = 256, r = 160, e = 256, q = 769,  m = 256, rqc = 256)  
    FLIT512 = FLITParameterSet(n = 2048, f = 896, g = 896, r = 896, e = 896, q = 3329, m = 512, rqc = 512)

# Compute the decryption failure probability of FLIT

# -- average case: random message (m ∈ {0,1}) --
F1, f1 = FLIT_decryption_failure_probability(FLIT128)
F2, f2 = FLIT_decryption_failure_probability(FLIT256)
F3, f3 = FLIT_decryption_failure_probability(FLIT512)

print("=== Average-case DFR (random message) ===")
print("FLIT128 decryption failure rate: %.1f = 2^%.1f"%(f1, log(f1 + 2.**(-1000))/log(2)))
print("FLIT256 decryption failure rate: %.1f = 2^%.1f"%(f2, log(f2 + 2.**(-1000))/log(2)))
print("FLIT512 decryption failure rate: %.1f = 2^%.1f"%(f3, log(f3 + 2.**(-1000))/log(2)))

# -- worst case: all-1s message (m ≡ 1) --
chi_m_1 = build_ternary_law(FLIT128.n, 0, FLIT128.n)  # P(1)=1
F1_w, f1_w = FLIT_decryption_failure_probability(FLIT128, chi_m=chi_m_1)
chi_m_1 = build_ternary_law(FLIT256.n, 0, FLIT256.n)
F2_w, f2_w = FLIT_decryption_failure_probability(FLIT256, chi_m=chi_m_1)
chi_m_1 = build_ternary_law(FLIT512.n, 0, FLIT512.n)
F3_w, f3_w = FLIT_decryption_failure_probability(FLIT512, chi_m=chi_m_1)

print("=== Worst-case DFR (all-1s message) ===")
print("FLIT128 decryption failure rate: %.1f = 2^%.1f"%(f1_w, log(f1_w + 2.**(-1000))/log(2)))
print("FLIT256 decryption failure rate: %.1f = 2^%.1f"%(f2_w, log(f2_w + 2.**(-1000))/log(2)))
print("FLIT512 decryption failure rate: %.1f = 2^%.1f"%(f3_w, log(f3_w + 2.**(-1000))/log(2)))

'''
=== Average-case DFR (random message) ===
FLIT128 decryption failure rate: 0.0 = 2^-187.5
FLIT256 decryption failure rate: 0.0 = 2^-176.1
FLIT512 decryption failure rate: 0.0 = 2^-195.5
=== Worst-case DFR (all-1s message) ===
FLIT128 decryption failure rate: 0.0 = 2^-177.8
FLIT256 decryption failure rate: 0.0 = 2^-164.5
FLIT512 decryption failure rate: 0.0 = 2^-191.0
'''