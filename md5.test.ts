import { md5, hash, HmacMD5, hashWithHmac } from "./md5";
const expect = require("expect");
const arrayBufferToHex = require("array-buffer-to-hex");

expect(md5("")).toBe("d41d8cd98f00b204e9800998ecf8427e");
expect(md5("helloworld")).toBe("fc5e038d38a57032085441e7fe7010b0");
expect(md5("123456789012345678901234567890123456789012345678901234567890")).toBe("c5b549377c826cc3712418b064fc417e");
expect(md5("花澤香菜")).toBe("3dac69ca69eeba37e0e40ef8ce856e56");
expect(md5("小倉唯")).toBe("59844b6674b4cf7dac5b150d7c32331b");
expect(arrayBufferToHex(hash(new Uint8Array([32, 48])).buffer)).toBe("0bad51c0b9b2ba77c19bf6bfbbf88dc3");
expect(HmacMD5("key", "helloworld")).toBe("1e5d13a56db53e511304b71aa4eab842");
expect(HmacMD5("小倉唯", "花澤香菜")).toBe("1bb4439879351a45a8977b3ad68d0b27");
expect(arrayBufferToHex(hashWithHmac(new Uint8Array([32, 48]), new Uint8Array([32, 49])).buffer)).toBe("56e1c5f6733a476b460049143d61214c");
