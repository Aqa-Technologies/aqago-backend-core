import { expect } from "chai"
import { createRandom } from "../src/random/utils.mjs"

describe("random", () => {
  it("should create a 32 character alphanumeric string", async () => {
    const random = createRandom(32)
    expect(random).to.match(/^[A-Z0-9]{32}$/)
  })
})
