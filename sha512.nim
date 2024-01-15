import std/[endians, strutils]

include sha2


const wordSize = 8
const blockSize = 128
const scheduleSize = 128

var w: array[scheduleSize, uint64]

type
  Sha512Context* = ref object
    state*: array[8, uint64]
    buffer: array[blockSize, uint8]
    bufferLen: int # NOTE: tracks the number of bytes currently in the buffer
    totalLen: int64 # NOTE: total length of the message

const initState: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
]
# NOTE: round constants
const k: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64,
    0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64, 0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64,
    0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64, 0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64, 0xc19bf174cf692694'u64,
    0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64, 0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
    0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64,
    0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64, 0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64,
    0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
    0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64, 0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64,
    0xd192e819d6ef5218'u64, 0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64, 0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64,
    0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64, 0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64,
    0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64,
    0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64, 0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64,
    0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64, 0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64, 0x431d67c49c100d4c'u64,
    0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64, 0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]


proc schedule(i: int): uint64 {.inline.} =
  ## modify message schedule values
  return sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16]


proc padBuffer(buffer: var array[blockSize, uint8], bufferLen: var int, totalLen: int64) =
  ## pad data in the buffer
  # NOTE: append the bit '1' to the buffer
  buffer[bufferLen] = 0x80'u8
  inc bufferLen

  # NOTE: pad with zeros until the last 64 bits
  while (bufferLen + 16) < blockSize:  # +16 for the 64-bit length at the end
    buffer[bufferLen] = 0'u8
    inc bufferLen

  # NOTE: add the original message length as a 128-bit big-endian integer
  # NOTE: upper 64 bits of the 128-bit length field are set to zero
  for i in countdown(15, 8):
    buffer[bufferLen] = 0'u8
    inc bufferLen
  
  # NOTE: add the lower 64 bits of the message length to the buffer
  let msgBitLength = uint64(totalLen * 8)
  for i in countdown(7, 0):
    buffer[bufferLen] = uint8((msgBitLength shr (i * 8)) and 0xff'u64)
    inc bufferLen


proc processBlock(state: var array[8, uint64], messageBlock: var array[blockSize, uint8]) =
  ## process single 1024 bit block
  # NOTE: fill in first 16 words in big endian64 format
  for i in 0 ..< 16:
    bigEndian64(addr w[i], addr messageBlock[i * wordSize])

  # NOTE: fill in remaining 112
  for i in 16 ..< scheduleSize:
    w[i] = schedule(i)

  # NOTE: initialize working variables to current hash value
  var a = state[0]
  var b = state[1]
  var c = state[2]
  var d = state[3]
  var e = state[4]
  var f = state[5]
  var g = state[6]
  var h = state[7]

  # NOTE: compression
  var temp1: uint64
  var temp2: uint64
  for i in 0 ..< 80:
    temp1 = h + Sigma1(e) + choice(e, f, g) + k[i] + w[i]
    temp2 = Sigma0(a) + majority(a, b, c)
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  # NOTE: add the compressed chunk to the current hash value
  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e
  state[5] += f
  state[6] += g
  state[7] += h


proc copyShaCtx*(toThisCtx: var Sha512Context, fromThisCtx: Sha512Context) =
  for idx, b in fromThisCtx.state:
    toThisCtx.state[idx] = b
  for idx, b in fromThisCtx.buffer:
    toThisCtx.buffer[idx] = b
  toThisCtx.bufferLen = fromThisCtx.bufferLen
  toThisCtx.totalLen = fromThisCtx.totalLen


proc update*[T](ctx: var Sha512Context, msg: openarray[T]) =
  ctx.totalLen.inc(msg.len)
  for i in 0 ..< msg.len:
    ctx.buffer[ctx.bufferLen] = uint8(msg[i])
    inc ctx.bufferLen
    if ctx.bufferLen == blockSize:
      processBlock(ctx.state, ctx.buffer)
      ctx.bufferLen = 0


proc finalize*(ctx: var Sha512Context) =
  # NOTE: pad the remaining data in the buffer
  padBuffer(ctx.buffer, ctx.bufferLen, ctx.totalLen)
  # NOTE: process the final block
  processBlock(ctx.state, ctx.buffer)


proc digest*(ctx: Sha512Context): array[64, uint8] =
  ## convert state array[8, uint64] to array[32, uint8]
  ## does not alter hash state
  var tempCtx: Sha512Context
  new tempCtx
  copyShaCtx(tempCtx, ctx)
  
  tempCtx.finalize()
  
  for idx, b in tempCtx.state:
    bigEndian64(addr result[idx * wordSize], unsafeAddr b)
  return result


proc hexDigest*(ctx: Sha512Context): string =
  ## convert state array[8, uint64] to hex string of length 128
  ## does not alter hash state
  var tempCtx: Sha512Context
  new tempCtx
  copyShaCtx(tempCtx, ctx)
  
  tempCtx.finalize()
  result = newStringOfCap(128)
  for h in tempCtx.state:
    result.add(h.toHex(16).toLowerAscii())
  return result


proc newSha512Ctx*(msg: openarray[uint8] = @[]): Sha512Context =
  # NOTE: initialize state
  new result
  result.state = initState
  if msg.len > 0:
    result.update(msg)


proc newSha512Ctx*(msg: string): Sha512Context =
  return newSha512Ctx(msg.toOpenArrayByte(0, msg.len.pred))


when isMainModule:
  let msg = "some test data"
  var hash = newSha512Ctx(msg)
  assert hash.hexDigest() == "4e03a727411d2f658aa530085ad642aec2b032df17f50c8b0b7f044a47017f142db659b14b846ea685d9cd128a78df2137611510e8f8ec139f1bed0a165fbfb8"
  hash.update("some more test data")
  assert hash.hexDigest() == "ed11592e6e6ab2dfdb98d69177da89f6e90743d257a00e7e5cf78af9cdca55def0515a41f5191fc2d6dc90c51eed760812ec70c20b8f25a9838de86bbb9d00b4"