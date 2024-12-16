import { expect } from "chai"
import {
  generateKeyPair,
  generateKeyPairEC,
  generateJWT,
  verifyJWT,
  decodeJWT,
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
  getCertInPemChain,
  getPemChainAsArray,
  validateX5cChain,
  prependCertToChain,
  derToPem,
} from "../src/pki/utils.mjs"

const AQAGO_TEST_CA_PUBLIC_CERT = `
-----BEGIN CERTIFICATE-----
MIIGBzCCA++gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZYxKjAoBgNVBAMMIWFx
YWdvLWJhY2tlbmQtY29yZS10ZXN0LXJvb3QtY2VydDELMAkGA1UEBhMCVVMxETAP
BgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9yazEfMB0GA1UECgwWQXFh
IFRlY2hub2xvZ2llcywgSW5jLjEUMBIGA1UECwwLRW5naW5lZXJpbmcwIBcNMjQx
MjE2MjE0MTI5WhgPMjA3NDEyMDQyMTQxMjlaMIGLMQswCQYDVQQGEwJVUzERMA8G
A1UECAwITmV3IFlvcmsxHzAdBgNVBAoMFkFxYSBUZWNobm9sb2dpZXMsIEluYy4x
FDASBgNVBAsMC0VuZ2luZWVyaW5nMTIwMAYDVQQDDClhcWFnby1iYWNrZW5kLWNv
cmUtdGVzdC1pbnRlcm1lZGlhdGUtY2VydDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAJIbpyt90gQ8DQwQCTeU5ehPk14vXN3zCdmCgRtyckFR8EtPrwzu
4Ps/JwEXWBQnIYX+Xv2El82m0PcbgMwQ1tjafDRnT3MvZahSs0NuQGlQJAk6DYbD
F+OAsxWNR1egNGQpfX9mf6NeMrok6W3hg9+A5XlDvLTNd3EzWIFo9ICU5cWpfEd+
Cjj5SJmBV3YHn1UjO5RMQ+CjIgeE87/u89s4+ehQVuZbkTbJemfOx+rqx7xhno2L
TpUSG3AKBur/aOY2u4qXDwYwsGg4xqHkyNzwmnvXWIaEmvyZCdnxgJ5uCcGIzt2j
hKAjGFmo8DSaIOmf3Km3Wq9qbztOitjEx1b+u8Kyf1q4umR96J2pwoDGwAWzuscc
uRL1nUPOpAlIGm6PqG9qMdjEnFCTtb4VxKPvfeTLfnXIgqAlx38sA3X8/sThR/Qk
vWy/TygciZufvJyYSpiPcguUE+JEce5eHmYWGaoT8ogEbxRI6sTxhM1D3g2RjE7m
5GDwQl33z3cFSA92REfaAvjZTnB6wQqHn8CQ8QzkL1X64AWBPUceGE1ePyxU3ABl
6xtqfkSBD/Xbd0HAo/42K9tP5D9XVZzyiFmcGjPeYm3Y5ffBBRb3TnCeEhFd5wd8
bNLAEtK3gD6D2mKQzng98AZuhaSXeIuq2hMTlvptfAN9n9CSGj8mF2ERAgMBAAGj
ZjBkMB0GA1UdDgQWBBRIyq83Y6K4Tk3O2SUGUT2+/ZfqbDAfBgNVHSMEGDAWgBR7
fUAttIlUHOxfhvG5PAwRJAskHTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB
/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAljHLbwbsz76olMz2MCRodFqSQVlM
5mQw2tQDDTOPaHSQ1+8Eqi560WscVTFNoE4Ty1WUSHwLjOHmhAN/pvUwVdYB3Bvy
LFmtrkP6YYYjRPSJzi2BMo1XhFpkrfHGL0Zss/82tkSA4XTY2J0yBrVjLH3ta/29
Ib29wKSoxAuDjkiSNj+XYMA23SuPy4FJgQbIytC+7GGwhwHroyO5NnDlSvTGY+hW
x/aND2qvUESWZHMUhtX2g749V+pfIVadEj7XMbp/QASKJa/WGt96Ijz0eNVmfXIs
ebsFXGIr4C+m5hnWcJn/6qXO5cdjfP3ssY/ctKVKLQhZGpUi9GKEZU740IimjUPr
/Loyd6ih6Ry9CqLW0iWCFCiLJRKKDKVyN9azd5ZzIe3kHsneq3JEjESMX2cvyQhl
76jgHVtHTRZdO9MAP8lG5ftonOOJwSQB4VOekgxP0WuhOAqW6Ny58vHn61USj12x
v6MGX/oEuLGn+1I+ipqZQNl9Tt2nRXVQOismjqFM+/GCHv54ksPywEmyvhshcRUd
cflWPInNn1xJPi4jsCQz73FdRiPjuNCDoBfU3eoIpT8cJ7OLet0fo6Pl45xRIPKS
D8DI5xLiTIxRlG7gdzkAJv3wBq2Sbr/n+FeLQK2yt5UziFss4xvMJK/QIv4RGqWk
6CK1A+hTLYtG5JA=
-----END CERTIFICATE-----`

const AQAGO_TEST_CA_PRIVATE_CERT = `
-----BEGIN PRIVATE KEY-----
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
/0pTEC3T0EUElxHjy9xQNau21XgM
-----END PRIVATE KEY-----`

const AQAGO_TEST_JWKS = {
  keys: [
    {
      kty: "RSA",
      n: "pIWBkdatsJzdPAmeeN9VfZozMS9tOk6r9deUQ59nkkusRkBWRBZ9NHNutGOVLxS337nDsMyu65VHNdtVfxrhVBRa_8yL0j1aKiqrrc4yhd1nusD1qFlZc66vwOvcgcgxgl5xU94N-h67N7V8ZdOQtYclS6ZwhNmKFR0FiKOkwhfAscomfrSnemqxJcUBYngTQ_q_NDXMwjQLlBdodtlLW4WHy3B_9kvdmAOQUtfEA7RynXTyOE_2MPjSXsLhxBeCqs2UbGou6olxpBifziO61lBaOTGcyNSRb8aq86gc_7aw0GUGrPg8PgJ4cYKUY8Vi0zP2vFPJ2RSGUkItM8Cibw",
      e: "AQAB",
      alg: "RS256",
      use: "sig",
      kid: "skzmw8ya",
      x5c: [
        "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",
      ],
    },
  ],
}

describe("pki", () => {
  describe("jwks flow", () => {
    it("should generate key pair", async () => {
      const { publicKey, privateKey } = generateKeyPair()
      expect(publicKey)
        .to.be.an("object")
        .that.includes.all.keys(["e", "kty", "n"])
      expect(publicKey).to.have.property("e").that.is.a("string")
      expect(publicKey).to.have.property("kty").that.is.a("string")
      expect(publicKey).to.have.property("n").that.is.a("string")
      expect(privateKey)
        .to.be.an("object")
        .that.includes.all.keys([
          "d",
          "dp",
          "dq",
          "e",
          "kty",
          "n",
          "p",
          "q",
          "qi",
        ])
    })
    it("should generate jwks", async () => {
      const { publicKey, privateKey } = generateKeyPair()
      const jwks = {
        keys: [
          {
            ...publicKey,
            use: "sig",
            alg: "RS256",
            kid: "test",
          },
        ],
      }
      expect(jwks).to.be.an("object").that.includes.all.keys(["keys"])
      expect(jwks.keys).to.be.an("array").that.has.lengthOf(1)
      expect(jwks.keys[0])
        .to.be.an("object")
        .that.includes.all.keys(["kty", "e", "n", "alg", "use", "kid"])
    })
    it("should issue jwt", async () => {
      const { privateKey } = generateKeyPair()
      const jwt = await generateJWT(privateKey, {
        sub: "test",
        iss: "test",
        aud: "test",
        exp: "1h",
        jwk_url: "https://localhost/.well-known/jwks.json",
      })
      expect(jwt).to.be.a("string")
    })
    it("should issue verifiable jwt", async () => {
      const { publicKey, privateKey } = generateKeyPair()
      const jwt = await generateJWT(privateKey, {
        sub: "test",
        iss: "test",
        aud: "test",
        exp: "1h",
        jwk_url: "https://localhost/.well-known/jwks.json",
      })
      const jwks = {
        keys: [
          {
            ...publicKey,
            use: "sig",
            alg: "RS256",
            kid: "test",
          },
        ],
      }
      const result = await verifyJWT(jwks.keys[0], jwt)
      expect(result)
        .to.be.an("object")
        .that.includes.all.keys(["payload", "protectedHeader"])
      expect(result.payload.sub).to.equal("test")
    })
    it("should issue decodable jwt", async () => {
      const { publicKey, privateKey } = generateKeyPair()
      const jwt = await generateJWT(privateKey, {
        sub: "test",
        iss: "test",
        aud: "test",
        exp: "1h",
        jwk_url: "https://localhost/.well-known/jwks.json",
      })
      const jwks = {
        ...publicKey,
        use: "sig",
        alg: "RS256",
        kid: "test",
      }
      const result = await decodeJWT(jwt)
      expect(result.jwk_url).to.equal("https://localhost/.well-known/jwks.json")
    })
    it("should not verify jwt from different jwks", async () => {
      const { privateKey } = generateKeyPair()
      const jwt = await generateJWT(privateKey, {
        sub: "test",
        iss: "test",
        aud: "test",
        exp: "1h",
        jwk_url: "https://localhost/.well-known/jwks.json",
      })
      const { publicKey } = generateKeyPair()
      const jwks = {
        ...publicKey,
        use: "sig",
        alg: "RS256",
        kid: "test",
      }
      try {
        await verifyJWT(jwks.keys[0], jwt)
      } catch (error) {
        expect(error).to.be.an("error")
      }
    })
  })
  describe("jws flow", () => {
    it("should sign jws", async () => {
      const { privateKey } = generateKeyPair()
      const jws = await signJWS(
        privateKey,
        { test: "test" },
        { header: { url: "https://example.com", nonce: "joij182jf" } }
      )
      expect(jws).to.be.a("string")
      return true
    })
    it("should verify jws", async () => {
      const { publicKey, privateKey } = generateKeyPairEC()
      const jws = await signJWS(
        privateKey,
        { test: "test" },
        {
          header: {
            url: "https://example.com",
            nonce: "joij182jf",
            jwk: publicKey,
          },
          alg: "ES256",
        }
      )
      const { payload, protectedHeader } = await verifyJWS(jws)
      expect(payload).to.be.an.instanceOf(Uint8Array)
    })
    it("should verifyJWSWithJWK", async () => {
      const { publicKey, privateKey } = generateKeyPairEC()
      const jws = await signJWS(
        privateKey,
        { test: "test" },
        {
          header: {
            url: "https://example.com",
            nonce: "joij182jf",
            jwk: publicKey,
          },
          alg: "ES256",
        }
      )
      const { payload } = await verifyJWSWithJWK(jws, publicKey)
      expect(payload).to.be.an.instanceOf(Uint8Array)
    })
    it("should decodeProtectedHeader", async () => {
      const { publicKey, privateKey } = generateKeyPairEC()
      const jws = await signJWS(
        privateKey,
        { test: "test" },
        {
          header: {
            url: "https://example.com",
            nonce: "joij182jf",
            jwk: publicKey,
          },
          alg: "ES256",
        }
      )
      const protectedHeader = decodeProtectedHeader(jws)
      expect(protectedHeader).to.be.a("object")
      expect(protectedHeader).to.have.property("alg").that.is.a("string")
      expect(protectedHeader).to.have.property("jwk").that.is.a("object")
      expect(protectedHeader)
        .to.have.property("url")
        .that.is.equals("https://example.com")
      expect(protectedHeader)
        .to.have.property("nonce")
        .that.is.equals("joij182jf")
    })
    it("should decode jws payload", async () => {
      const { publicKey, privateKey } = generateKeyPairEC()
      const jws = await signJWS(
        privateKey,
        { test: "test" },
        {
          header: {
            url: "https://example.com",
            nonce: "joij182jf",
            jwk: publicKey,
          },
          alg: "ES256",
        }
      )
      const { payload } = await verifyJWS(jws)
      const decodedPayload = JSON.parse(decodeJWSPayload(payload))
      expect(decodedPayload).to.be.a("object")
      expect(decodedPayload).to.deep.equal({ test: "test" })
    })
  })
  describe("csr", () => {
    it("should generate a valid csr", async () => {
      const csr = generateCSR(
        generateKeyPair(),
        [
          {
            name: "commonName",
            value: "aqago.com",
          },
          {
            name: "countryName",
            value: "US",
          },
          {
            shortName: "ST",
            value: "New York",
          },
          {
            name: "localityName",
            value: "New York",
          },
          {
            name: "organizationName",
            value: "Aqa Technologies, Inc.",
          },
          {
            shortName: "OU",
            value: "Aqago",
          },
        ],
        [
          {
            name: "extensionRequest",
            extensions: [
              {
                name: "basicConstraints",
                cA: true,
                pathLen: 0,
              },
              {
                name: "keyUsage",
                keyCertSign: true,
                digitalSignature: true,
                cRLSign: true,
              },
              {
                name: "extKeyUsage",
                codeSigning: true,
              },
              {
                name: "subjectAltName",
                altNames: [
                  {
                    // type 2 is DNS
                    type: 2,
                    value: "test.domain.com",
                  },
                  {
                    type: 2,
                    value: "other.domain.com",
                  },
                  {
                    type: 2,
                    value: "www.domain.net",
                  },
                ],
              },
            ],
          },
        ]
      )
      expect(csr).to.be.a("string")
      expect(verifyCSR(csr)).to.be.true
    })
    it("should issue a CA cert from a valid csr", async () => {
      const csr = generateCSR(
        generateKeyPair(),
        [
          {
            name: "commonName",
            value: "aqago.com",
          },
          {
            name: "countryName",
            value: "US",
          },
          {
            shortName: "ST",
            value: "New York",
          },
          {
            name: "localityName",
            value: "New York",
          },
          {
            name: "organizationName",
            value: "Aqa Technologies, Inc.",
          },
          {
            shortName: "OU",
            value: "Aqago",
          },
        ],
        [
          {
            name: "extensionRequest",
            extensions: [
              {
                name: "basicConstraints",
                cA: true,
                pathLen: 0,
              },
              {
                name: "keyUsage",
                keyCertSign: true,
                digitalSignature: true,
                cRLSign: true,
              },
              {
                name: "extKeyUsage",
                codeSigning: true,
              },
              {
                name: "subjectAltName",
                altNames: [
                  {
                    // type 2 is DNS
                    type: 2,
                    value: "test.domain.com",
                  },
                  {
                    type: 2,
                    value: "other.domain.com",
                  },
                  {
                    type: 2,
                    value: "www.domain.net",
                  },
                ],
              },
            ],
          },
        ]
      )
      const cert = issueCertificateFromCSR(
        csr,
        {
          public: AQAGO_TEST_CA_PUBLIC_CERT,
          private: AQAGO_TEST_CA_PRIVATE_CERT,
        },
        "0",
        {
          notBefore: new Date(),
          notAfter: new Date(new Date().setMonth(new Date().getMonth() + 14)),
        }
      )
    })
  })
  describe("chains", () => {
    it("getCertInPemChain", async () => {
      const cert = getCertInPemChain(AQAGO_TEST_CA_PUBLIC_CERT)
      expect(cert).to.be.a("string")
    })
    it("prependCertToChain", async () => {
      const chain = prependCertToChain(
        AQAGO_TEST_CA_PUBLIC_CERT,
        AQAGO_TEST_CA_PUBLIC_CERT
      )
      expect(chain).to.be.a("string")
      const first = getCertInPemChain(chain)
      const second = getCertInPemChain(chain, 1)
      expect(first).to.equal(second)
    })
    it("getPemChainAsArray", async () => {
      const chain = prependCertToChain(
        AQAGO_TEST_CA_PUBLIC_CERT,
        AQAGO_TEST_CA_PRIVATE_CERT
      )
      expect(chain).to.be.a("string")
      for (const [i, cert] of getPemChainAsArray(chain).entries()) {
        expect(cert).to.be.a("string")
        expect(cert).to.equal(getCertInPemChain(chain, i))
      }
    })
    it("validateX5cChain", async () => {
      expect(
        validateX5cChain(
          AQAGO_TEST_JWKS.keys[0].x5c.map((x) =>
            derToPem(Buffer.from(x, "base64").toString("binary"))
          )
        )
      ).to.be.true
    })
  })
  describe("conversions", () => {
    it("pemToJWK", async () => {
      let jwk = pemToJWK(AQAGO_TEST_CA_PUBLIC_CERT)
      expect(jwk).to.be.an("object")
      expect(jwk).to.have.property("kty").that.is.a("string")
      expect(jwk).to.have.property("n").that.is.a("string")
      expect(jwk).to.have.property("e").that.is.a("string")
      jwk = pemToJWK(AQAGO_TEST_CA_PRIVATE_CERT)
      expect(jwk).to.be.an("object")
      expect(jwk).to.have.property("kty").that.is.a("string")
      expect(jwk).to.have.property("n").that.is.a("string")
      expect(jwk).to.have.property("e").that.is.a("string")
    })
    it("pemToDer", async () => {
      const der = Buffer.from(pemToDer(AQAGO_TEST_CA_PUBLIC_CERT)).toString(
        "base64"
      )
      expect(der).to.be.a("string")
    })
    it("thumbprintFromPem", () => {
      const { publicKey } = generateKeyPairEC({ format: "pem" })
      const thumbprint = thumbprintFromPem(publicKey)
      expect(thumbprint).to.be.a("string")
    })
  })
})
