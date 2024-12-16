import { expect } from "chai"
import { generateKeyPair } from "../src/pki/utils.mjs"
import { provisionToHostedIntermediateCA } from "../src/ca/utils.mjs"

describe("ca", () => {
  describe("provisionToHostedIntermediateCA", () => {
    it("should provision", async () => {
      const keyPair = generateKeyPair()
      const res = await provisionToHostedIntermediateCA(
        "https://api.eca.dev.aqago.com/csr",
        keyPair
      )
      expect(res).to.be.true
    })
  })
})
