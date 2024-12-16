function createRandom(length, type = "alphanumeric") {
  var alphabet = ""
  switch (type) {
    case "alphanumeric":
      alphabet = "abcdefghjkmnpqrstuvwxyz123456789"
      break
    case "numeric":
      alphabet = "123456789"
      break
    default:
      throw new Error("Invalid type")
  }

  var str = ""
  for (let i = 0; i < length; i++) {
    str += alphabet.charAt(Math.floor(Math.random() * alphabet.length))
  }
  return str
}

export { createRandom }
