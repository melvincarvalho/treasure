#!/usr/bin/env node
// Usage: node spot-cli.mjs <npub|hex> [bits]
import { findSpot, checkSpot, npubDecode, npubEncode, taprootAddress } from './spot.js'

const [arg, b = '20'] = process.argv.slice(2)
if (!arg) { console.error('usage: spot-cli.mjs <npub|hex> [bits]'); process.exit(1) }
const hex = arg.startsWith('npub') ? npubDecode(arg) : arg.toLowerCase()
const t0 = performance.now()
const s = findSpot(hex, { bits: Number(b) })
const secs = (performance.now() - t0) / 1000
console.log(JSON.stringify({
  npub: npubEncode(hex),
  pubkey: hex,
  rule: `first point with >= ${b} zeros`,
  i: s.i,
  depth: s.depth,
  spot: s.x,
  spotNpub: npubEncode(s.x),
  address: taprootAddress(s.x),
  verified: checkSpot(hex, s.i, s.x),
  seconds: +secs.toFixed(2)
}, null, 2))
