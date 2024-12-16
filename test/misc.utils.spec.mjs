import { expect } from "chai"
import { getSha256 } from "../src/misc/utils.mjs"

describe("misc", () => {
  it("getSha256", async () => {
    const sha256 = getSha256("test")
    expect(sha256.length).to.equal(64)
  })
})
