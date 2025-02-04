import {
  generateKeyPairSync,
  createHash,
  createPublicKey,
  createPrivateKey,
} from "crypto"
import forge from "node-forge"
import * as jose from "jose"

function generateKeyPairEC({ format = "jwk" } = {}) {
  return generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: {
      type: "spki",
      format,
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format,
    },
  })
}

function generateKeyPair({ format = "jwk" } = {}) {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format,
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format,
    },
  })
}

async function generateJWT(jwk, { sub, iss, aud, exp, ...custom }) {
  return await new jose.SignJWT(custom ?? {})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setExpirationTime(exp)
    .sign(await jose.importJWK(jwk))
}

async function verifyJWT(jwk, jwt) {
  return await jose.jwtVerify(jwt, await jose.importJWK(jwk))
}

async function decodeJWT(jwt) {
  return jose.decodeJwt(jwt)
}

function derToPem(der) {
  return forge.pki.certificateToPem(
    forge.pki.certificateFromAsn1(forge.asn1.fromDer(der))
  )
}

function pemToJWK(pem, { type = "public", encoding = "spki" } = {}) {
  switch (type) {
    case "public":
      return createPublicKey(pem).export({ format: "jwk", type: encoding })
    case "private":
      return createPrivateKey(pem).export({ format: "jwk", type: encoding })
    default:
      throw new Error("Invalid key type")
  }
}

function pemToDer(pem) {
  return forge.pki.pemToDer(pem).getBytes()
}

function thumbprintFromPem(pem) {
  return createHash("sha256")
    .update(forge.pki.pemToDer(pem).toHex(), "hex")
    .digest("hex")
}

async function signJWS(
  jwk,
  payload,
  { header = {}, alg = "RS256", serialization = "compact" } = {}
) {
  switch (serialization) {
    case "compact":
      return await new jose.CompactSign(
        new TextEncoder().encode(JSON.stringify(payload))
      )
        .setProtectedHeader({ alg, ...header })
        .sign(await jose.importJWK(jwk))
    case "flattened":
      return await new jose.FlattenedSign(
        new TextEncoder().encode(JSON.stringify(payload))
      )
        .setProtectedHeader({ alg, ...header })
        .sign(await jose.importJWK(jwk))
    default:
      throw new Error("Invalid serialization")
  }
}

async function verifyJWS(jws, options = { serialization: "compact" }) {
  const { jwk, jku, kid } = jose.decodeProtectedHeader(jws)
  if (!jwk && !jku) throw new Error("JWK or JKU is required")
  const key =
    jwk ||
    (await fetch(jku)
      .then((res) => res.json())
      .then((json) => json.keys.find((k) => k.kid === kid)))
  if (!key) throw new Error("JWK not found")
  return await verifyJWSWithJWK(jws, key, options)
}

async function verifyJWSWithJWK(jws, jwk, { serialization = "compact" } = {}) {
  switch (serialization) {
    case "compact":
      return await jose.compactVerify(jws, jwk)
    case "flattened":
      return await jose.flattenedVerify(jws, jwk)
    default:
      throw new Error("Invalid serialization")
  }
}

function decodeProtectedHeader(jws) {
  return jose.decodeProtectedHeader(jws)
}

function decodeJWSPayload(payload) {
  return new TextDecoder().decode(payload)
}

function generateCSR(
  keyPair,
  subject,
  attributes,
  { keyPairFormat = "jwk" } = {}
) {
  const csr = forge.pki.createCertificationRequest()
  let publicKey = null
  if (keyPairFormat === "pem") {
    publicKey = keyPair.publicKey
  } else {
    publicKey = createPublicKey({
      key: keyPair.publicKey,
      format: "jwk",
    }).export({
      type: keyPair.publicKey.kty === "EC" ? "spki" : "pkcs1",
      format: "pem",
    })
  }
  csr.publicKey = forge.pki.publicKeyFromPem(publicKey)
  csr.setSubject(subject)
  if (attributes) {
    csr.setAttributes(attributes)
  }
  csr.sign(
    forge.pki.privateKeyFromPem(
      createPrivateKey({
        key: keyPair.privateKey,
        format: keyPairFormat,
      }).export({
        type: "pkcs8",
        format: "pem",
      })
    )
  )
  return forge.pki.certificationRequestToPem(csr)
}

function verifyCSR(csr) {
  return forge.pki.certificationRequestFromPem(csr).verify()
}

function issueCertificateFromCSR(csr, issuer, serialNumber, validity) {
  const cert = forge.pki.createCertificate()
  cert.publicKey = forge.pki.certificationRequestFromPem(csr).publicKey
  cert.serialNumber = serialNumber
  cert.validity = validity
  cert.setIssuer(forge.pki.certificateFromPem(issuer.public).subject.attributes)
  cert.setSubject(forge.pki.certificationRequestFromPem(csr).subject.attributes)
  cert.setExtensions(
    forge.pki
      .certificationRequestFromPem(csr)
      .getAttribute({ name: "extensionRequest" }).extensions
  )
  cert.sign(
    forge.pki.privateKeyFromPem(issuer.private),
    forge.md.sha256.create()
  )
  return forge.pki.certificateToPem(cert)
}

function getCommonNameFromCSR(csr) {
  return forge.pki.certificationRequestFromPem(csr).subject.getField("CN").value
}

function getCertInPemChain(pem, position = 0) {
  return forge.pem.encode(forge.pem.decode(pem)[position])
}

function getPemChainAsArray(chain) {
  return forge.pem.decode(chain).map(forge.pem.encode)
}

function validateX5cChain(chain) {
  return forge.pki.verifyCertificateChain(
    forge.pki.createCaStore([
      forge.pki.certificateFromPem(getPemChainAsArray(chain).pop()),
    ]),
    chain.map(forge.pki.certificateFromPem)
  )
}

function prependCertToChain(cert, chain) {
  return [...forge.pem.decode(cert), ...(forge.pem.decode(chain) ?? [])]
    .map(forge.pem.encode)
    .map((pem) => pem + "\n")
    .join("")
}

export {
  generateKeyPair,
  generateKeyPairEC,
  generateJWT,
  verifyJWT,
  decodeJWT,
  derToPem,
  pemToJWK,
  pemToDer,
  thumbprintFromPem,
  signJWS,
  verifyJWS,
  verifyJWSWithJWK,
  decodeProtectedHeader,
  decodeJWSPayload,
  generateCSR,
  verifyCSR,
  issueCertificateFromCSR,
  getCommonNameFromCSR,
  getCertInPemChain,
  getPemChainAsArray,
  validateX5cChain,
  prependCertToChain,
}
