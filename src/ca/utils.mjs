import { generateJWT } from "../pki/utils.mjs"
//import axios from "axios"

async function provisionToHostedIntermediateCA(url, keyPair) {
  return true
  const jwt = await generateJWT(keyPair.privateKey, {
    sub: "aqago-backend-tenant",
    iss: "aqago-backend-tenant",
    aud: "aqago-eca",
    exp: "1h",
    jwk_url:
      "https://zns3jbl3d8.execute-api.us-east-1.amazonaws.com/v1/.well-known/jwks.json",
  })
  try {
    const response = await axios.post(url, null, {
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
    })
    console.log(response.data)
  } catch (error) {
    console.error("Error making POST request:", error)
    throw error
  }
  return true
}

export { provisionToHostedIntermediateCA }
