## Schnorr Batch

项目完成人： 王庆华

### 1、Schnorr数字签名算法简单流程

Setup:
$$
\begin{aligned}
& \mathrm{x}:=\text { random number } \quad \text { (aka private key) } \\
& \mathrm{G}:=\text { common point } \\
& \mathrm{X}:=\mathrm{x}{ }^{\star} \mathrm{G} \quad \text { (aka public key) }
\end{aligned}
$$


Sign:
$$
\begin{aligned}
& r:=r a n d o m \text { number (aka nonce) } \\
& R:=r * G \quad \text { (aka commitment) } \\
& e:=\text { Hash } R, X \text {, message)(aka challenge) } \\
& \mathrm{s}:=r+e* x \quad \text { (aka response) } \\
& \text { return }(R, X, s \text {, message) } \quad((s, e) \text { aka signature) }
\end{aligned}
$$
Verify:
$$
\begin{aligned}
& \text { receive }(R, X, s, \text { message }) \\
& \text { e }:=\operatorname{Hash}(R, X \text {, message }) \\
& \mathrm{s} 1:=R+e* X \\
& \mathrm{~s} 2:=\mathrm{s}* \mathrm{G}\\
& \text {return OK if S1 qeuals S2} \\
\end{aligned}
$$



### 2、schnorr batch verify

![](https://img1.imgtp.com/2023/07/11/xHFxjOpY.png)

只有三个签名同时验证成功batch才能验证成功

代码运行结果：

![](https://img1.imgtp.com/2023/07/11/pav6LwRA.png)

可见时间减少了一半
