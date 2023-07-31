# implement sm2 2P decrypt with real network communication
![](https://img1.imgtp.com/2023/07/31/9FQCcsIY.png)
## 代码说明
先运行client2，再运行client1
## 流程
### client1

1.Generate sub private key $$d_1 \in[1, n-1]$$

2.get ciphertext $$C=C_1||C_2||C_3$$
   Check$$ C_1 \neq\ 0$$
   Compute $$ T_1=d_1^{-1}*G$$
   Send$$T_1$$

4.Recover plaintext$$M'$$,receive$$T_2$$

​       Compute$$T_2-C_1=(x_2,y_2)=[(d_1d_2)^{-1}-1]*C_1=kp$$

​       Compute$$t=KDF(x_2||y_2,klen)$$

​        Compute$$M"=C_2\oplus t$$

​        Compute$$u=Hash(x_2||M"||y_2)$$

​         If $$u=C_3,output M"$$

### Client2
1.Generate sub private key$$d_2 \in[1, n-1]$$
3.Compute$$T_2=d_2^{-1}*T_1$$

## 椭圆曲线参数选取
![](https://img1.imgtp.com/2023/07/31/mUo5HE9X.png)
## 运行结果
![](https://img1.imgtp.com/2023/07/31/ZRRv8lWJ.png)