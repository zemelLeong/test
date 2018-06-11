# utils
## 数据加密模块
python3.6.5测试通过
加密库安装：pip install pycrypto

非对称加密使用示例：  
&emsp;&emsp;实例化一个对象：  
&emsp;&emsp;&emsp;&emsp;
```
obj = DataEncryption.AsymmetricEncryption()
```  
&emsp;&emsp;生成公钥及私钥：  
&emsp;&emsp;&emsp;&emsp;
```
public_key, private_key = obj.generate_secret_key(length=1024)
```  
&emsp;&emsp;对数据进行加密、签名，私钥是可选的，如不传入则相应的签名为None：  
&emsp;&emsp;&emsp;&emsp;
```
data, sig = obj.data_encryption_signer(source_data=s, pub_key=public_key)
```  
&emsp;&emsp;使用私钥对数据进行解密：  
&emsp;&emsp;&emsp;&emsp;
```
d_data = obj.decrypt(data, private_key)
```