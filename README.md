# lifegpc-md5
A Node.js module for hashing messages with MD5.
## Function
```JavaScript
const md5 = require("lifegpc-md5");
md5.md5("test"); // 098f6bcd4621d373cade4e832627b4f6
// The string will encode with UTF-8
md5.md5("中文"); // a7bac2239fcdcb3a067903d8077c4a07
// UInt8Array is also supported.
md5.hash(new Uint8Array([32, 48])) // Uint8Array(16) [11, 173, 81, 192, 185, 178, 186, 119, 193, 155, 246, 191, 187, 248, 141, 195]
// HmacMD5
md5.HmacMD5("key", "helloworld") // 1e5d13a56db53e511304b71aa4eab842
// Uint8Array(16) [86, 225, 197, 246, 115, 58, 71, 107, 70, 0, 73, 20, 61, 97, 33, 76]
md5.hashWithHmac(new Uint8Array([32, 48]), new Uint8Array([32, 49]))
```
