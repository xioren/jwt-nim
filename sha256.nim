import std/[endians, strutils]

include sha2

# NOTE: the original version with a 256-bit digest

const wordSize = 4
const blockSize = 64
const scheduleSize = 64

# NOTE: schedule array
var w: array[scheduleSize, uint32]

type
  Sha256Context* = object
    state*: array[8, uint32]
    buffer: array[blockSize, uint8]
    bufferLen: int  # NOTE: tracks the number of bytes currently in the buffer
    totalLen: int64 # NOTE: total length of the message

const initState: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
]
# NOTE: round constants
const k: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]


proc schedule(i: int): uint32 {.inline.} =
  ## modify message schedule values
  return sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16]


proc padBuffer(ctx: var Sha256Context) =
  ## pad data in the buffer
  # NOTE pad with zeros until the last 64 bits
  while ctx.bufferLen < blockSize - 8:  # -8 for the 64-bit length at the end
    ctx.buffer[ctx.bufferLen] = 0'u8
    inc ctx.bufferLen
  
  # NOTE: add the original message length as a 64-bit big-endian integer
  let msgBitLength = uint64(ctx.totalLen * 8)
  for i in countdown(7, 0):
    ctx.buffer[ctx.bufferLen] = uint8((msgBitLength shr (i * 8)) and 0xff'u64)
    inc ctx.bufferLen
    

proc compress(ctx: var Sha256Context) =
  ## process single 512 bit block
  # NOTE: fill in first 16 words in big endian32 format
  for i in 0 ..< 16:
    bigEndian32(addr w[i], addr ctx.buffer[i * wordSize])
  # NOTE: fill in remaining 48
  for i in 16 ..< scheduleSize:
    w[i] = schedule(i)

  # NOTE: initialize working variables to current hash value
  var a = ctx.state[0]
  var b = ctx.state[1]
  var c = ctx.state[2]
  var d = ctx.state[3]
  var e = ctx.state[4]
  var f = ctx.state[5]
  var g = ctx.state[6]
  var h = ctx.state[7]

  # NOTE: compression
  var temp1: uint32
  var temp2: uint32
  for i in 0 ..< scheduleSize:
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
  ctx.state[0] += a
  ctx.state[1] += b
  ctx.state[2] += c
  ctx.state[3] += d
  ctx.state[4] += e
  ctx.state[5] += f
  ctx.state[6] += g
  ctx.state[7] += h

  ctx.bufferLen = 0


proc copyShaCtx*(toThisCtx: var Sha256Context, fromThisCtx: Sha256Context) =
  for idx, b in fromThisCtx.state:
    toThisCtx.state[idx] = b
  for idx, b in fromThisCtx.buffer:
    toThisCtx.buffer[idx] = b
  toThisCtx.bufferLen = fromThisCtx.bufferLen
  toThisCtx.totalLen = fromThisCtx.totalLen


proc update*[T](ctx: var Sha256Context, msg: openarray[T]) =
  ## move message into buffer and process as it fills.
  ctx.totalLen.inc(msg.len)
  for i in 0 ..< msg.len:
    ctx.buffer[ctx.bufferLen] = uint8(msg[i])
    inc ctx.bufferLen
    if ctx.bufferLen == blockSize:
      ctx.compress()


proc finalize*(ctx: var Sha256Context) =
  # NOTE: append the bit '1' to the buffer guaranteeing at least 1 byte free
  ctx.buffer[ctx.bufferLen] = 0x80'u8
  inc ctx.bufferLen
  
  # NOTE: compress data in the buffer if it contains more than blockSize - 8 bytes.
  # this ensures there is room for the length field
  if ctx.bufferLen >= blockSize - 8:
    ctx.compress()
  
  # NOTE: pad the remaining data in the buffer
  ctx.padBuffer()
  # NOTE: process the final block
  ctx.compress()


proc digest*(ctx: Sha256Context): array[32, uint8] =
  ## convert state array[8, uint32] to array[32, uint8]
  ## does not alter hash state
  var tempCtx: Sha256Context
  copyShaCtx(tempCtx, ctx)
  
  tempCtx.finalize()
  
  for idx in 0 ..< 8:
    bigEndian32(addr result[idx * wordSize], addr tempCtx.state[idx])

  return result


proc hexDigest*(ctx: Sha256Context): string =
  ## convert state array[8, uint32] to hex string of length 64
  ## does not alter hash state
  var tempCtx: Sha256Context
  copyShaCtx(tempCtx, ctx)
  
  tempCtx.finalize()
  
  result = newStringOfCap(64)
  for idx in 0 ..< 8:
    result.add(tempCtx.state[idx].toHex(8).toLowerAscii())
  return result


proc newSha256Ctx*(msg: openarray[uint8] = @[]): Sha256Context =
  # NOTE: initialize state
  result.state = initState
  if msg.len > 0:
    result.update(msg)


proc newSha256Ctx*(msg: string): Sha256Context =
  return newSha256Ctx(msg.toOpenArrayByte(0, msg.len.pred))
