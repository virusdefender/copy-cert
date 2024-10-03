# copy-cert

在资产测绘和应急响应的时候，大家可能更加关注 ssl 证书的签发者、有效期、序列号、域名等信息，并作为威胁情报采集的依据，而忽略了去校验证书的有效性。
本工具可以基于已知网站 ssl 证书的信息生成新的自签名证书，保持签发者、有效期、序列号、域名等一致，用于伪装流量。

参考资料 [C2基础设施威胁情报对抗策略](https://www.anquanke.com/post/id/291324)

## 用法

在 Release 中下载二进制或者自行编译，然后 `copy-cert $addr`，比如 `copy-cert baidu.com:443` 然后就可以得到几个证书和私钥文件。

```
➜  2024_10_03_14_28_41 git:(main) ✗ tree
.
├── DigiCert_Secure_Site_Pro_CN_CA_G3.crt
├── DigiCert_Secure_Site_Pro_CN_CA_G3.key
├── bundle.crt
├── bundle.key
├── www.baidu.cn.crt
└── www.baidu.cn.key
```

其中 bundle 为合并证书链之后的文件。

## demo

![](assets/real-aliyun.png)

![](assets/self-signed-aliyun.png)
