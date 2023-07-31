# implement sm2 2P sign with real network communication
## 流程
Public key :
$$
P=\left[\left(d_1 d_2\right)^{-1}-1\right] G
$$
Private key：
$$
d=\left(d_1 d_2\right)^{-1}-1
$$
### 一、client1
1.生成私钥$$d_1 \in[1, n-1]$$，计算$$P_1=d_1^{-1} \cdot G$$，发送p1至client2
3.（1）计算$$M^{\prime}=Z \| M, e=\operatorname{Hash}\left(M^{\prime}\right)$$
（2）选取$$k_1 \in[1, n-1]$$，计算$$Q_1=k_1 G$$
（3）发送$$Q_1，e$$至client2
5.生成签名$$\sigma=(r, s)$$
（1）$$s=\left(d_1 * k_1\right) * s_2+d_1 * s_3-r \bmod n$$
（2）$$\text { If } s \neq 0 \text { or } s \neq n-r \text {, output signature } \sigma=(r, s)$$
### 二、client2
2.（1）接受p1，生成私钥$$d_2 \in[1, n-1]$$
（2）生成公钥$$P=d_2^{-1} \cdot P_1-G$$，公开公钥
4.（1）接收$$Q_1，e$$
（2）生成$$k_2 \in[1, n-1]$$，计算$$Q_2=k_2 G$$
生成$$k_3 \in[1, n-1]$$，计算$$k_3 Q_1+Q_2=\left(x_1, y_1\right)$$
（3）计算$$r=x_1+e \bmod n(r \neq 0)$$
计算$$s_2=d_2 \cdot k_3 \bmod n$$
计算$$s_3=d_2\left(r+k_2\right) \bmod n$$
（4）发送$$r,s_2,s_3$$至client1
![](https://img1.imgtp.com/2023/07/28/YlMvuYJZ.png)
## 椭圆曲线参数选取
![](https://img1.imgtp.com/2023/07/31/mUo5HE9X.png)
## 运行结果
![](https://img1.imgtp.com/2023/07/28/HHCT1TpL.png)