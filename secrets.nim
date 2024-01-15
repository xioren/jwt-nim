import std/[base64, math, strutils, sysrand]

# NOTE: implementation of Python's secrets library in nim
# (including getrandbits and _randbelow_with_getrandbits from Python's random library)

const defaultEntropy = 32

proc tokenBytes*(nBytes: Positive = 0): seq[byte]


proc getRandBits(k: Positive): uint64 =
  ## Generates an int with k random bits
  if k <= 0:
    raise newException(ValueError, "Number of bits must be positive")
  if k > 64:
    raise newException(ValueError, "Number of bits must not exceed 64")

  let numBytes = (k + 7) div 8 # calculate how many bytes are needed
  let randomBytes = tokenBytes(numBytes)

  for i, b in randomBytes:
    result = result or (uint64(b) shl (i * 8))
  result = result shr (numBytes * 8 - k)

  return result


proc randbelow(exclusiveUpperBound: Positive): Natural =
    ## Return a random int in the range [0, exclusiveUpperBound)
    if exclusiveUpperBound <= 0:
      raise newException(ValueError, "Upper bound must be positive.")

    let k = int(ceil(log2(float(exclusiveUpperBound))))
    result = getRandBits(k)
    while result >= exclusiveUpperBound:
      result = getRandBits(k)

    return result


proc tokenBytes*(nBytes: Positive = 0): seq[byte] =
  ## Return a random byte string containing *nBytes* bytes
  if nBytes <= 0:
    return urandom(defaultEntropy)
  return urandom(nBytes)


proc tokenHex*(nBytes: Positive = 0): string =
  ## Return a random text string, in hexadecimal
  result = newStringOfCap(nBytes + nBytes)
  let tb = tokenBytes(nBytes)
  for b in tb:
    result.add(toHex(b))
  return result


proc tokenUrlSafe*(nBytes: Positive = 0): string =
    ## Return a random URL-safe text string, in Base64 encoding
    let tok = tokenBytes(nBytes)
    return encode(tok, safe=true).strip(chars={'='}, leading=false)


when isMainModule:
  # echo tokenBytes(8)
  echo tokenHex(8)
  # echo tokenUrlSafe(128)
  # echo getRandBits(10)
  # echo randBelow(50)
