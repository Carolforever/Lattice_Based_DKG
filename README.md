## 项目名称
> 基于格密码的DKG demo



## 相关参数
* Number of participants (N): 6
* Threshold (T):              2
* sigma_x:                    1.00
* sigma_y:                    18.36 (= √337 × sigma_x)
* slack_factor：              10.0
* Algebraic setting:          Module lattice R_q^k
   * – Base ring R_q:         ℤ_q[X]/(X^8+1)
   * – Modulus q:             12289
   * – Ring dimension n:      8
   * – Module rank k (d):     4
* bound：                     slack_factor * σ_v * sqrt(d * ring_degree)
* Encryption:                 X25519 KEM + AES-256-GCM (Ed25519 signatures)



## 运行条件
* Python 3.10.12 及以上
* 安装所有导入的包
* 在项目根目录克隆铜锁项目：https://github.com/Tongsuo-Project/Tongsuo.git，并编译安装



## 运行说明
* 在项目根目录，运行 python3 V3S_DKG.py
