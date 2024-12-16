import { createHash } from "crypto"

function getSha256(str) {
  return createHash("sha256").update(str).digest("hex")
}

export { getSha256 }
