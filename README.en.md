# Rsa Random Aes Pay Crypt

#### Description
使用ras+aes加密传输数据的java实现

#### Software Architecture
由于:RSA加密是有长度限制的.单纯用RSA加密较长数据时得使用分段加密,效率低下.用RSA+AES是比较主流的做法:AES加密数据产生密文,RSA加密AES密钥产生加密后的AES密钥,然后将密文和加密后的AES密钥一起传输