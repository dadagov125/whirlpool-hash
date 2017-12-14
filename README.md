# Whirlpool hash for JavaScript/TypeScript
Calculates WHIRLPOOL (WHIRLPOOL-0, WHIRLPOOL-T) hash

LICENSE MIT

## Examples

Install:
```npm
npm i whirlpool-hash
```


Using on JavaScript(ES6)/TypeScript:
```typescript
import {Whirlpool,encoders}  from 'whirlpool-hash'

let whirlpool = new Whirlpool()
let hash=whirlpool.getHash("message")
encoders.toBase64(hash)
encoders.fromBase64('bWVzc2FnZQ==')
encoders.toHex('message')
```

