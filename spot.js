// Treasure spot: the first point on a key's walk P+G, P+2G, … with at least `bits`
// leading zero bits in its 32-byte x-coordinate. About 2^bits steps on average.
// P is the BIP340 even-y lift of an x-only Nostr pubkey. Pure BigInt, no deps.

const p = 2n ** 256n - 2n ** 32n - 977n
const n = 2n ** 256n - 0x14551231950b75fc4402da1732fc9bebfn
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
]

const mod = (a, m = p) => { a %= m; return a < 0n ? a + m : a }
function inv (a, m = p) {
  let [r0, r1, s0, s1] = [m, mod(a, m), 0n, 1n]
  while (r1) { const q = r0 / r1;[r0, r1] = [r1, r0 - q * r1];[s0, s1] = [s1, s0 - q * s1] }
  return mod(s0, m)
}
function powmod (b, e) { let r = 1n; b = mod(b); while (e) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n } return r }

// Affine point ops; null is the point at infinity.
function add (P, Q) {
  if (!P) return Q
  if (!Q) return P
  if (P[0] === Q[0]) {
    if (mod(P[1] + Q[1]) === 0n) return null
    const l = mod(3n * P[0] * P[0] * inv(2n * P[1]))
    const x = mod(l * l - 2n * P[0])
    return [x, mod(l * (P[0] - x) - P[1])]
  }
  const l = mod((Q[1] - P[1]) * inv(Q[0] - P[0]))
  const x = mod(l * l - P[0] - Q[0])
  return [x, mod(l * (P[0] - x) - P[1])]
}
export function mul (k, P = G) {
  let R = null
  for (k = mod(k, n); k; k >>= 1n, P = add(P, P)) if (k & 1n) R = add(R, P)
  return R
}

export function liftX (x) {
  if (x <= 0n || x >= p) throw new Error('x out of range')
  const y = powmod(x ** 3n + 7n, (p + 1n) / 4n)
  if (y * y % p !== mod(x ** 3n + 7n)) throw new Error('x is not on the curve')
  return [x, y & 1n ? p - y : y]
}

export const zeroBits = x => 256 - x.toString(2).length

// Walk i = 1, 2, 3 … in N lanes (lane j starts at P+(j+1)G, steps by N·G), sharing one
// inversion per round, until a point has >= bits zeros. Lanes are read in increasing i,
// so the first hit is the lowest i. onProgress(done, expected, records) runs per round.
export function findSpot (xHex, { bits = 20, lanes = 1024, onProgress } = {}) {
  const N = lanes
  const P = liftX(BigInt('0x' + xHex))
  const L = [add(P, G)]
  for (let j = 1; j < N; j++) L.push(add(L[j - 1], G))
  const NG = mul(BigInt(N))
  const pre = new Array(N)
  // records are the landmarks: each point deeper than every one before it
  let best = -1
  const records = []
  for (let base = 1; ; base += N) {
    for (let j = 0; j < N; j++) {
      const d = zeroBits(L[j][0])
      if (d > best) {
        best = d
        records.push({ i: base + j, depth: d })
        if (d >= bits) return { i: base + j, depth: d, x: L[j][0].toString(16).padStart(64, '0'), records }
      }
    }
    // batched step: every lane += N·G
    let acc = 1n
    for (let j = 0; j < N; j++) { pre[j] = acc; acc = acc * mod(NG[0] - L[j][0]) % p }
    let ia = inv(acc)
    for (let j = N - 1; j >= 0; j--) {
      const [x, y] = L[j]
      const dx = ia * pre[j] % p
      ia = ia * mod(NG[0] - x) % p
      const l = mod((NG[1] - y) * dx)
      const nx = mod(l * l - x - NG[0])
      L[j] = [nx, mod(l * (x - nx) - y)]
    }
    if (onProgress) onProgress(base + N - 1, 2 ** bits, records)
  }
}

// Check a claimed spot cheaply: P + i·G has this x (does not prove no earlier point qualifies).
export function checkSpot (xHex, i, spotHex) {
  return add(liftX(BigInt('0x' + xHex)), mul(BigInt(i)))[0] === BigInt('0x' + spotHex)
}

// Spending key for the spot: k + i, negated if needed so the spot point has even y.
export function spotSecret (kHex, i) {
  let k = BigInt('0x' + kHex)
  if (mul(k)[1] & 1n) k = n - k // match the even-y lift of P
  let s = mod(k + BigInt(i), n)
  if (mul(s)[1] & 1n) s = n - s
  return s.toString(16).padStart(64, '0')
}

// A fresh random secret key in [1, n-1], as hex.
export function randomSecret () {
  for (;;) {
    const b = globalThis.crypto.getRandomValues(new Uint8Array(32))
    const k = BigInt('0x' + [...b].map(x => x.toString(16).padStart(2, '0')).join(''))
    if (k > 0n && k < n) return k.toString(16).padStart(64, '0')
  }
}
export const pubkeyOf = kHex => mul(BigInt('0x' + kHex))[0].toString(16).padStart(64, '0')

// bech32 / bech32m
const CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
function polymod (v) {
  const g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let c = 1
  for (const x of v) { const b = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >> i) & 1) c ^= g[i] }
  return c >>> 0
}
const hrpx = h => [...h].map(c => c.charCodeAt(0) >> 5).concat(0, [...h].map(c => c.charCodeAt(0) & 31))
function bits (data, from, to, pad) {
  let a = 0; let b = 0; const r = []
  for (const x of data) { a = (a << from) | x; b += from; while (b >= to) { b -= to; r.push((a >> b) & ((1 << to) - 1)) } }
  if (pad && b) r.push((a << (to - b)) & ((1 << to) - 1))
  return r
}
const hexBytes = h => h.match(/../g).map(b => parseInt(b, 16))
function encode (hrp, data, k) {
  const m = polymod(hrpx(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ k
  return hrp + '1' + data.concat([0, 1, 2, 3, 4, 5].map(i => (m >>> (5 * (5 - i))) & 31)).map(d => CS[d]).join('')
}
export const npubEncode = hex => encode('npub', bits(hexBytes(hex), 8, 5, true), 1)
export const nsecEncode = hex => encode('nsec', bits(hexBytes(hex), 8, 5, true), 1)
// Bare-key taproot output (no BIP86 tweak), so the zeros show in the address.
export const taprootAddress = (hex, hrp = 'tb') => encode(hrp, [1].concat(bits(hexBytes(hex), 8, 5, true)), 0x2bc830a3)

export function npubDecode (s) {
  s = s.toLowerCase()
  const at = s.lastIndexOf('1')
  const hrp = s.slice(0, at)
  const d = [...s.slice(at + 1)].map(c => CS.indexOf(c))
  if (hrp !== 'npub' || d.includes(-1) || polymod(hrpx(hrp).concat(d)) !== 1) throw new Error('bad npub')
  return bits(d.slice(0, -6), 5, 8, false).map(b => b.toString(16).padStart(2, '0')).join('')
}
