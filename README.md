# Project-Implement-the-above-ECMH-scheme
实施上述ECMH方案：椭圆曲线哈希族

首先我们由课程中讲述UTXO Commitment的实现方法之一 Elliptic curve MultiSet Hash

全节点的同步问题，可以让新的全节点快速启动，目前，比特币的模式下要启动一个全结点，需要下载从创世区块到最新区块所有的区块。目前，所有区块的大小约为几百G。其实用全结点去验证新交易，我们其实直接操作的是UTXO集合，看一下新的交易是否引用UTXO集合的某个UTXO。

UTXO集合其实就是比特币系统目前的状态，所以要启动一个全节点理论上只需要下载某个区块和该区块对应的UTXO集合即可，UTXO集合的大小约为几个G（<<几百G），其与历史数据不同，可以被消耗，所以它不会像历史数据那样线性增加。当然，这样会丢失前面所有的历史交易的记录。然而，怎么保证下载的UTXO集合和某个区块能够对上？这里就引入了UTXO Commitment。就是把UTXO集合的摘要写到比特币的区块上。

UTXO Commitment的实现方式
朴素的方式【1】
按某个键排列所有UTXO，然后把他们连接起来进行哈希
这样的问题在于：
随着新区块的加入，UTXO集合中会有UTXO被消费以及新的UTXO被消费。因此，需要重新把几G的UTXO集合重新排序，算哈希。但是这样可能会出现意料之外的问题！
因此，下面引入了哈希求和算法
哈希求和算法

对集合中的每个UTXO进行哈希，然后把所有的哈希加起来作为这个UTXO集合的哈希结果。每接收一个新区块，就用UTXO集合的哈希减去花费的UTXO哈希&加上新增的UTXO哈希。

![图片](https://user-images.githubusercontent.com/107350922/179759883-ceff9bc3-d5df-4f9e-8d63-0978794ca490.png)

这里存在一个问题，这个算法没那么安全，假设当前UTXO集合哈希为S，我想伪造的交易为T，那么我只需要找到另外哈希值为S-T的交易即可。此处还有进一步弱化，UTXO集合的数量不确定，允许很多中排列组合，安全性进一步降低。

用hash-then-add方法去哈希集合存在的其他问题：
https://jameshfisher.com/2018/01/09/how-to-hash-multiple-values.html
ECMH哈希算法：Elliptic curve MultiSet Hash

思路

就是把哈希映射成椭圆曲线上的点，然后利用ECC的加法。

我们进一步思考为什么比一般的哈希求和算法要安全？

更安全的意思是要达到相同的安全性，ECMH算法需要的密钥长短远远小于哈希求和算法。

我个人觉得更安全与椭圆曲线类型的密钥有关，举个例子就是RSA在相同的安全性的条件下，需要的密钥长度远远长于ECC的。所以ECMH需要先映射到椭圆曲线，再继续进行同态加法【2】。

参考资料：
【1】https://blog.csdn.net/weixin_34346099/article/details/92411938
【2】https://blog.csdn.net/jason_cuijiahui/article/details/86711927
