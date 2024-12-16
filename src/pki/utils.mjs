import {
  generateKeyPairSync,
  randomUUID,
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

function generateKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "jwk",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "jwk",
    },
  })
}

function generateJWKS(publicKey) {
  return {
    keys: [
      {
        kty: publicKey.kty,
        e: publicKey.e,
        n: publicKey.n,
        alg: "RS256",
        use: "sig",
        kid: randomUUID(),
      },
    ],
  }
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

async function signJWSES256(jwk, payload, header = {}) {
  return await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader({ alg: "ES256", jwk, ...header })
    .sign(await jose.importJWK(jwk))
}

async function verifyJWS(jws, { serialization = "compact" } = {}) {
  const protectedHeader = jose.decodeProtectedHeader(jws)
  switch (serialization) {
    case "compact":
      return await jose.compactVerify(jws, protectedHeader.jwk)
    case "flattened":
      return await jose.flattenedVerify(jws, protectedHeader.jwk)
    default:
      throw new Error("Invalid serialization")
  }
}

async function verifyJWSWithJWK(jws, jwk) {
  return await jose.compactVerify(jws, jwk)
}

function decodeProtectedHeader(jws) {
  return jose.decodeProtectedHeader(jws)
}

function decodeJWSPayload(payload) {
  return JSON.parse(new TextDecoder().decode(payload))
}

function generateCSR(keyPair, subject, attributes) {
  const csr = forge.pki.createCertificationRequest()
  csr.publicKey = forge.pki.publicKeyFromPem(
    createPublicKey({ key: keyPair.publicKey, format: "jwk" }).export({
      type: "pkcs1",
      format: "pem",
    })
  )
  csr.setSubject(subject)
  if (attributes) {
    csr.setAttributes(attributes)
  }
  csr.sign(
    forge.pki.privateKeyFromPem(
      createPrivateKey({ key: keyPair.privateKey, format: "jwk" }).export({
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
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
      pathLen: 0,
    },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyCertSign: true,
      cRLSign: true,
    },
    {
      name: "extKeyUsage",
      codeSigning: true,
      clientAuth: true,
    },
    {
      name: "subjectAltName",
      altNames: [
        {
          type: 2,
          value: forge.pki
            .certificationRequestFromPem(csr)
            .subject.getField("CN").value,
        },
      ],
    },
  ])
  cert.sign(forge.pki.privateKeyFromPem(issuer.private))
  return forge.pki.certificateToPem(cert)
}

export {
  generateKeyPair,
  generateKeyPairEC,
  generateJWKS,
  generateJWT,
  verifyJWT,
  decodeJWT,
  signJWSES256,
  verifyJWS,
  verifyJWSWithJWK,
  decodeProtectedHeader,
  decodeJWSPayload,
  generateCSR,
  verifyCSR,
  issueCertificateFromCSR,
}
