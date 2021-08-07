const fs = require("fs");

if (fs.existsSync("lib/md5.js")) {
    let f = fs.readFileSync("lib/md5.js", {"encoding": "utf-8"})
    let l = f.split('\n');
    let r = [];
    let fi = true;
    for (let i = 0; i < l.length; i++) {
        let s = l[i];
        if (s.startsWith('exports.') && s.endsWith('= void 0;') && fi) continue;
        if (s == '"use strict";');
        else if (s.startsWith('Object.defineProperty(exports,'));
        else fi = false;
        r.push(s);
    }
    let t = r.join('\n');
    fs.writeFileSync("lib/md5.js", t, {"encoding": "utf-8"});
}
