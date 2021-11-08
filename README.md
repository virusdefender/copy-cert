# cert-copier

基于已知网站 ssl 证书的信息生成新的自签名证书，除了证书是不被信任的以外，其他的信息看上去基本一致。

## 用法

在 Release 中下载二进制或者自行编译，然后 `cert-copier $addr`，比如 `cert-copier github.com:443` 然后就可以得到几个证书和私钥文件。

```
➜  certs git:(main) tree
.
├── DigiCert_High_Assurance_TLS_Hybrid_ECC_SHA256_2020_CA1.crt
├── DigiCert_High_Assurance_TLS_Hybrid_ECC_SHA256_2020_CA1.key
├── bundle.crt
├── bundle.key
├── github.com.crt
└── github.com.key
```

其中 bundle 为合并证书链之后的文件。

## 用途

 - 伪装流量

## demo

![](assets/real-aliyun.png)

![](assets/self-signed-aliyun.png)
