const fs = require('fs');
const content = fs.readFileSync('src/app.js', 'utf8');
const targets = new Set();
const suspect = /[縺繧莉蠕繝蜷邂陝蟋吁蜍蟇蜊蜴蜿蛟險譌譛讎髢驕蟷螂遘郁蛹蟾蛯蜻蛤蜿螳蟈蠡逶邏鬚邨]/;
let i = 0;
while (i < content.length) {
  const ch = content[i];
  if (ch === '"' || ch === '\'' || ch === '`') {
    const quote = ch;
    let j = i + 1;
    let str = '';
    while (j < content.length) {
      const c = content[j];
      if (c === '\\') {
        if (j + 1 < content.length) {
          str += c + content[j + 1];
          j += 2;
          continue;
        }
        break;
      }
      if (c === quote) {
        break;
      }
      str += c;
      j += 1;
    }
    if (suspect.test(str)) {
      targets.add(str);
    }
    i = j + 1;
  } else {
    i += 1;
  }
}
console.log(Array.from(targets).join('\n---\n'));
