import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { findSpot, checkSpot, spotSecret, mul, liftX, zeroBits, npubEncode, npubDecode, nsecEncode, taprootAddress, randomSecret, pubkeyOf } from './spot.js'

const agent = '86fd7c96590583bac17c47145e634ac8afa0fa3a3f97d76c4ce7b7bfc0b82bba'
const hex = k => k.toString(16).padStart(64, '0')

// encodings match values computed independently earlier (sidestr whoami, rana)
assert.equal(taprootAddress(agent), 'tb1psm7he9jeqkpm4stugu29uc62ezh6p73687tawmzvu7mmls9c9waqyqxcy3')
assert.equal(npubDecode(npubEncode(agent)), agent)
assert.equal(npubDecode('npub1qqq9fpyqk06s87ch6p7zk7pefpzq3n4n62kfpg526xklq4u2dtgqcmtmlm'),
  '0000548480b3f503fb17d07c2b7839484408ceb3d2ac90a28ad1adf0578a6ad0')
assert.equal(zeroBits(0x0000548480b3f503fb17d07c2b7839484408ceb3d2ac90a28ad1adf0578a6ad0n), 17)

// reference: walk by scalar multiplication alone, x(P + iG) = x((k+i)G) up to sign of k
function reference (k, bits) {
  const kk = mul(k)[1] & 1n ? -k : k // P is the even-y lift
  for (let i = 1; ; i++) {
    const d = zeroBits(mul(kk + BigInt(i))[0])
    if (d >= bits) return { depth: d, i }
  }
}

for (let t = 0; t < 4; t++) {
  const k = BigInt('0x' + randomBytes(32).toString('hex'))
  const x = hex(mul(k)[0])
  const ref = reference(k, 8)
  for (const lanes of [1, 7, 64, 1024]) {
    const s = findSpot(x, { bits: 8, lanes })
    assert.deepEqual({ depth: s.depth, i: s.i }, ref, `lanes=${lanes}`)
    assert.ok(s.depth >= 8)
    assert.ok(checkSpot(x, s.i, s.x))
    assert.ok(!checkSpot(x, s.i + 1, s.x))
    // landmarks: strictly deeper, in step order, ending at the spot
    const r = s.records
    assert.deepEqual(r.at(-1), { i: s.i, depth: s.depth })
    for (let q = 1; q < r.length; q++) assert.ok(r[q].i > r[q - 1].i && r[q].depth > r[q - 1].depth)
  }
  // the owner's key k controls the spot: spotSecret·G has the spot's x and even y
  const s = findSpot(x, { bits: 12 })
  const S = mul(BigInt('0x' + spotSecret(hex(k), s.i)))
  assert.equal(hex(S[0]), s.x)
  assert.equal(S[1] & 1n, 0n)
}

// random key: pubkey matches, and its spot secret controls the spot
{
  const sk = randomSecret()
  const x = pubkeyOf(sk)
  assert.equal(x, hex(mul(BigInt('0x' + sk))[0]))
  const s = findSpot(x, { bits: 12 })
  assert.equal(pubkeyOf(spotSecret(sk, s.i)), s.x)
  assert.match(nsecEncode(sk), /^nsec1[02-9ac-hj-np-z]{58}$/)
}
// NIP-19 test vector
assert.equal(nsecEncode('67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa'),
  'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5')

// liftX rejects x values that are not on the curve
assert.throws(() => liftX(5n))
console.log('all spot tests passed')
