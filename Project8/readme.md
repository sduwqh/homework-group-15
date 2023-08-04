# Project8: AES impl with ARM instruction
## AES算法介绍
加密流程：
![1690989930179.png](https://img1.imgtp.com/2023/08/02/B4a0LTsm.png)
轮密钥生成流程:
![1690989965187.png](https://img1.imgtp.com/2023/08/02/OrJfPMEH.png)
解密过程:
解密过程仍为10轮，每一轮的操作是加密操作的逆操作。由于AES的4个轮操作都是可逆的，因此，解密操作的一轮就是顺序执行逆行移位、逆字节代换、轮密钥加和逆列混合。同加密操作类似，最后一轮不执行逆列混合，在第1轮解密之前，要执行1次密钥加操作。
## ARM 介绍

ARM 处理器是一系列基于精简指令集计算机（RISC）架构的中央处理单元（CPU）。ARM 就是“高级精简指令集机器（Advanced RISC Machine）”的简写。与人们更为熟悉的服务器架构（如 x86）相比，ARM 架构代表了一种不同的系统硬件设计方法。

AES-NI，这是针对AES加密算法的硬件加解密CPU指令集。可以大大加速aes算法运行速度。

原因如下：

1. 硬件加速：指令集提供了专用的硬件电路来执行AES加密和解密，因此不再需要在软件层面实现这些操作，从而提高了加密和解密的速度。
2. 并行处理：指令集允许处理多个数据块同时执行，利用了ARM处理器的SIMD（单指令，多数据）能力，进一步提高了AES算法的性能。
3. 低功耗：使用硬件加速的AES指令能够在更短的时间内完成加密和解密操作，从而减少CPU的工作负载，节省了功耗。

## ARM指令集实现AES算法
### 指令集各函数介绍：
根据arm64指令集在线文档（https://developer.arm.com/），介绍指令如下：
vld1q_u8：
是ARM NEON指令集中用于加载数据块（128位，即16字节）的指令。它用于从内存中加载一块连续的数据，例如一个数组或一个数据块，并将数据存储在一个128位的ARM NEON向量寄存器中。

vst1q_u8：
该函数是用于ARM NEON向量存储操作的汇编指令，用于将128位数据块（16字节）从ARM NEON寄存器存储到内存中。

vaeseq_u8：
是ARM NEON指令集中用于AES加密算法的一个指令。它用于执行AES加密算法的中间步骤——行移位（ShiftRows）和字节代换（SubBytes）。其部分伪代码如下：

```c
if decrypt then
    result = AESInvSubBytes(AESInvShiftRows(result));
else
    result = AESSubBytes(AESShiftRows(result));
```

vaesmcq_u8:
是ARM NEON指令集中用于AES加密算法的一个指令。它用于对一个128位的数据块进行AES加密算法的中间步骤——列混淆（MixColumns）。其部分伪代码如下：

```c
if decrypt then
    result = AESInvMixColumns(operand);
else
    result = AESMixColumns(operand);
```

veorq_u8:
用于ARM NEON向量按位异或操作，根据操作类型和向量寄存器的值执行不同的按位操作，并将结果存储回指定的向量寄存器。其部分伪代码如下：

```c
case op of
    when VBitOp_VEOR
        operand1 = V[m];
        operand2 = Zeros();
        operand3 = Ones();
    when VBitOp_VBSL
        operand1 = V[m];
        operand2 = operand1;
        operand3 = V[d];
    when VBitOp_VBIT
        operand1 = V[d];
        operand2 = operand1;
        operand3 = V[m];
    when VBitOp_VBIF
        operand1 = V[d];
        operand2 = operand1;
        operand3 = NOT(V[m]);
```
### 代码实现
```C
#include <stdio.h>
#include <stdint.h>
#include <arm64_neon.h>
#加密函数
void ase128_enc_armv8(const uint8_t in[16], uint8_t ou[16],
    const uint32_t rk[44]) {
    uint8x16_t block = vld1q_u8(in);

    uint8_t* p8 = (uint8_t*)rk;
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 0)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 1)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 2)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 3)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 4)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 5)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 6)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 7)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 8)));
    #最后一轮跳过列混淆
    block = vaeseq_u8(block, vld1q_u8(p8 + 16 * 9));
    block = veorq_u8(block, vld1q_u8(p8 + 16 * 10));

    vst1q_u8(ou, block);
}
#解密函数
void aes128_dec_armv8(const uint8_t in[16], uint8_t ou[16],
    const uint32_t rk[44]) {
    uint8x16_t block = vld1q_u8(in);

    uint8_t* p8 = (uint8_t*)rk;
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 0)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 1)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 2)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 3)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 4)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 5)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 6)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 7)));
    block = vaesimcq_u8(vaesdq_u8(block, vld1q_u8(p8 + 16 * 8)));
    block = vaesdq_u8(block, vld1q_u8(p8 + 16 * 9));
    block = veorq_u8(block, vld1q_u8(p8 + 16 * 10));

    vst1q_u8(ou, block);
}
#轮密钥拓展函数
void generate_AES_keys(const uint8_t in[16], uint32_t rk[44]) {
    uint32_t* roundKey = rk;
    const uint8_t* key = in;
    uint32_t temp;
    uint8_t i = 0;

    // Copy the original key to the first round key
    while (i < 4) {
        roundKey[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
        ++i;
    }

    i = 4;

    // Generate the remaining round keys
    while (i < 44) {
        temp = roundKey[i - 1];

        if (i % 4 == 0) {
            // Perform the key schedule core
            temp = (temp << 8) | (temp >> 24);

            // Apply S-box substitution
            temp = (Sbox[(temp >> 24) & 0xFF] << 24) |
                (Sbox[(temp >> 16) & 0xFF] << 16) |
                (Sbox[(temp >> 8) & 0xFF] << 8) |
                (Sbox[temp & 0xFF]);

            temp ^= Rcon[i / 4];
        }

        roundKey[i] = roundKey[i - 4] ^ temp;
        ++i;
    }
}

```

### 代码运行
Visual Studio 2022已经配置了支持arm指令集编译的arm64_neon.h头文件。但不幸的是，虽然能够将其链接到程序，却会出现报错：#error This header is specific to ARM64 targets.也就是说， x64 编译器不能包含 ARM 代码。
当我访问了微软的开发者社区的相关贴子之后，我发现Visual Studio的开发团队似乎并未解决 这个问题，故我尝试使用ARM64 msvc编译器。
在Visual Studio 2022，点击工具->获取工具和功能，即可打开Visual Studio Installer。在这里搜索并下载最新的arm64 msvc生成工具。
下载并安装完毕后，点击配置管理器，配置Visual Studio 2022的活动解决方案平台。如下图所示。
![1691047475762.png](https://img1.imgtp.com/2023/08/03/3Okrm4qx.png)
这时点击生成解决方案，即可成功生成可执行文件armaes.exe，如下图：
![1691047580917.png](https://img1.imgtp.com/2023/08/03/x8OtLKS1.png)
为调试可执行文件，我安装并运行了Visual Studio 2022 远程调试器。
如下是我的调试记录。为了防止可能出现的认证问题，这里选择关闭身份验证。

![1691047183443.png](https://img1.imgtp.com/2023/08/03/yv3xpuMK.png)

但在项目属性中配置好远程调试参数后，运行exe文件报错：程序“[16676] armaes.exe”已退出，返回值为 3221225785 (0xc0000139) 'Entry Point Not Found'。尚不知道如何解决。推测是dll文件缺失。但移动相关dll文件并未能解决这个问题。
查找相关资料显示ARM64 架构的程序不支持在 X86 架构的 Windows 上运行，只能在 `ARM64` 上运行。
但我们可以验证生成的可执行文件是否是ARM64架构，来证明我们是否成功生成了由ARM指令集编写的AES加密算法的可执行文件。
这里采用微软提供的二进制文件转储器dumpbin.exe。显示有关通用对象文件格式 (COFF) 的二进制文件的信息。
可以使用 DUMPBIN 检查 COFF 对象文件、 COFF 对象、 可执行文件和动态链接库 (Dll) 的标准库。
也可用来验证一个程序是否为 ARM64 架构。
在Visual Studio 2022的调试窗口下选择开放者powershell，键入指令：dumpbin.exe /headers “可执行文件全路径”，即可检查一个exe文件的相关信息。
![1691050594184.png](https://img1.imgtp.com/2023/08/03/pRsnWGLt.png)

如图所示，运行结果中出现 AA64 machine (ARM64) ，即代表该可执行文件为 ARM64 架构。
即成功生成了ARM64架构的AES算法可执行文件。
故认为成功完成了ARM指令集下的AES算法实现。