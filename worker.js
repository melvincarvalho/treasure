// Runs the treasure-spot walk off the main thread.
import { findSpot, checkSpot } from './spot.js'

onmessage = ({ data: { pubkey, bits } }) => {
  try {
    const t0 = performance.now()
    let last = 0
    const s = findSpot(pubkey, {
      bits,
      onProgress (done, total, records) {
        const now = performance.now()
        if (now - last > 50) { last = now; postMessage({ type: 'progress', done, total, records }) }
      }
    })
    postMessage({ type: 'done', ...s, verified: checkSpot(pubkey, s.i, s.x), ms: performance.now() - t0 })
  } catch (e) {
    postMessage({ type: 'error', message: e.message })
  }
}
