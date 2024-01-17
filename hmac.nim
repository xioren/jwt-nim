import sequtils

import sha256, sha512


type
  DigestMod* = enum
    SHA256, SHA512

  HmacContext* = object
    digestMod*: DigestMod
    sha256Ctx*: Sha256Context
    sha512Ctx*: Sha512Context
    oKeyPad, iKeyPad: seq[uint8]


proc copyHmacCtx*(toThisCtx: var HmacContext, fromThisCtx: HmacContext) {.inline.} =
  toThisCtx.digestMod = fromThisCtx.digestMod

  if not fromThisCtx.sha256Ctx.isNil:
    copyShaCtx(toThisCtx.sha256Ctx, fromThisCtx.sha256Ctx)
  if not fromThisCtx.sha512Ctx.isNil:
    copyShaCtx(toThisCtx.sha512Ctx, fromThisCtx.sha512Ctx)
  
  toThisCtx.oKeyPad = newSeq[uint8](fromThisCtx.oKeyPad.len)
  toThisCtx.iKeyPad = newSeq[uint8](fromThisCtx.iKeyPad.len)
  for idx, b in fromThisCtx.oKeyPad:
    toThisCtx.oKeyPad[idx] = b
  for idx, b in fromThisCtx.iKeyPad:
    toThisCtx.iKeyPad[idx] = b


proc update*[T](ctx: var HmacContext, msg: openarray[T]) =
  case ctx.digestMod
  of SHA256:
    ctx.sha256Ctx.update(msg)
  of SHA512:
    ctx.sha512Ctx.update(msg)


proc finalize*(ctx: var HmacContext) =
  case ctx.digestMod
  of SHA256:
    ctx.sha256Ctx.finalize()
  of SHA512:
    ctx.sha512Ctx.finalize()


proc digest*(ctx: var HmacContext): seq[uint8] {.inline.} =
  case ctx.digestMod
  of SHA256:
    var outerCtx = newSha256Ctx(ctx.oKeyPad)
    outerCtx.update(ctx.sha256Ctx.digest())
    return outerCtx.digest().toSeq()
  of SHA512:
    var outerCtx = newSha512Ctx(ctx.oKeyPad)
    outerCtx.update(ctx.sha512Ctx.digest())
    return outerCtx.digest().toSeq()


proc hexDigest*(ctx: HmacContext): string =
  case ctx.digestMod
  of SHA256:
    var tempShaCtx = newSha256Ctx()
    copyShaCtx(tempShaCtx, ctx.sha256Ctx)
    
    var outerCtx = newSha256Ctx(ctx.oKeyPad)
    outerCtx.update(tempShaCtx.digest())
    return outerCtx.hexDigest()
  of SHA512:
    var tempShaCtx = newSha512Ctx()
    copyShaCtx(tempShaCtx, ctx.sha512Ctx)
    
    var outerCtx = newSha512Ctx(ctx.oKeyPad)
    outerCtx.update(tempShaCtx.digest())
    return outerCtx.hexDigest()


proc initHmac(ctx: var HmacContext, key: openarray[uint8]) =
  case ctx.digestMod
  of SHA256:
    const blockSize = 64
    
    # NOTE: normalize key
    var keyBytes: array[blockSize, uint8]
    # NOTE: hash key if it is larger than block size, otherwise copy it directly into keyBytes
    if key.len > blockSize:
      var hash = newSha256Ctx(key)
      for i, b in hash.digest():
        keyBytes[i] = b
    else:
      for i, b in key:
        keyBytes[i] = b

    # NOTE: create inner and outer padded keys
    ctx.iKeyPad = newSeq[uint8](blockSize)
    ctx.oKeyPad = newSeq[uint8](blockSize)
    for i, b in keyBytes:
      ctx.iKeyPad[i] = b xor 0x36
      ctx.oKeyPad[i] = b xor 0x5c
    
    # NOTE: init sha context
    ctx.sha256Ctx = newSha256Ctx(ctx.iKeyPad)
  of SHA512:
    const blockSize = 128
   
    # NOTE: normalize key
    var keyBytes: array[blockSize, uint8]
    # NOTE: hash key if it is larger than block size, otherwise copy it directly into keyBytes
    if key.len > blockSize:
      var hash = newSha512Ctx(key)
      for i, b in hash.digest():
        keyBytes[i] = b
    else:
      for i, b in key:
        keyBytes[i] = b

    # NOTE: create inner and outer padded keys
    ctx.iKeyPad = newSeq[uint8](blockSize)
    ctx.oKeyPad = newSeq[uint8](blockSize)
    for i, b in keyBytes:
      ctx.iKeyPad[i] = b xor 0x36
      ctx.oKeyPad[i] = b xor 0x5c
    
    # NOTE: init sha context
    ctx.sha512Ctx = newSha512Ctx(ctx.iKeyPad)


proc newHmacCtx*(key: openarray[uint8], msg: openarray[uint8] = @[], digestMod: DigestMod): HmacContext =
  result.digestMod = digestMod
  result.initHmac(key) 
  if msg.len > 0:
    result.update(msg)

  return result


proc newHmacCtx*(key: string, msg: string = "", digestMod: DigestMod): HmacContext =
  return newHmacCtx(key.toOpenArrayByte(0, key.len.pred), msg.toOpenArrayByte(0, msg.len.pred), digestMod)


when isMainModule:
  let key = "your-secret-key"
  let message = "your-message"

  var hmac256 = newHmacCtx(key, message, digestMod=SHA256)
  var hmac512 = newHmacCtx(key, message, digestMod=SHA512)

  assert hmac256.hexDigest() == "85af3c047c3d807cb870748905d81ad4b1833e1928ba1dc59d45e84f546fbf9f"
  assert hmac512.hexDigest() == "f3f9a54180e33ff0ca7cd1d563b98bb5cd75161bce2bbec2d9621fa96a9c47212eaa5c4208bfea68b3ccd79aa026d245affa200a21429b2a02b9be3fa663bccc"

  hmac256.update("more-of-your-message")
  hmac512.update("more-of-your-message")

  assert hmac256.hexDigest() == "31458f4fea72ca51cab0151894589ac9d6ec6d569b53099405c9ad307f7825e0"
  assert hmac512.hexDigest() == "de7f03db3638d7f8f45128b5a8633f71cc91073bf3b6cf4d7c9307cb767f8dfb0aa7def66788c17060938a92896923893a20ab0d18a41a2dd7cc0a7686932026"
