const { strictEqual } = require('assert')
const verifier = require('../lib/main')

// a real token is used to check caching behavior.
// It will expire at some point.
const player = {
  'gamePlayerID': 'A:_650ed1e2127d4e11098d1521e3b7d076',
  'teamPlayerID': 'T:_2d60bf58179cc5774b0473446c5ae683'
}
const testToken = {
  publicKeyUrl: "https://static.gc.apple.com/public-key/gc-prod-5.cer",
  timestamp: 1615458137079,
  signature: "HpC8l7Uj+UaTxAZvxYsrQjYXU1lxNFzteX5iVqrnVJTVWlWvf9nH66NvKDyw8zjVdtNUQFOzJjYHnWsWQbanqHKRhbP/uVh/uNKJBpAe56/3QKSjtMkpdY32TNgWmXE219ve/isOk9MSRozowO1kEJ60X8TcVglKmoTyXFA4Vo02i7RvpLJWNLvu/Sk+BIlpt54OX1qE+hgjVYiAFKMPGdfaHlIwNwtR5JgrlpwBPOdYL8lG526v6Fw6yraGqUyeQGUbdQ6Yi3V+YN0t6BOVArtyNKGaKIKmaCfS1C3NA7ntGfM0u/KnbDEACDs8dA4skCXivHZySIEFsaZprW8ymw==",
  salt: "9Rmrxw==",
  bundleId: "net.triband.tricloud-test1",
  playerId: player.teamPlayerID,
}

describe('caching test', function () {
  it('should be slow for first check', async function () {
    this.timeout(5_000)
    const verified = await verifier.verify(testToken, false)
    strictEqual(verified, true, "expected verification to succeed")
  })

  it('should take less time for next checks due to caching', async function () {
    const times = 1000
    const targetAvgMs = 30
    this.timeout(times * targetAvgMs)

    for (let i = 0; i < times; i++) {
      const verified = await verifier.verify(testToken, true)
      strictEqual(verified, true, "expected verification to succeed")
    }
  })
})

