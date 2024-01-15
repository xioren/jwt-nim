# NOTE: common sha-2 functions

func rotateRight(x: uint32, n: int): uint32 {.inline.} =
  return (x shr n) or (x shl (32 - n))


func rotateRight(x: uint64, n: int): uint64 {.inline.} =
  return (x shr n) or (x shl (64 - n))


func choice(x, y, z: uint32): uint32 {.inline.} =
  return (x and y) xor ((not x) and z)


func choice(x, y, z: uint64): uint64 {.inline.} =
  return (x and y) xor ((not x) and z)


func majority(x, y, z: uint32): uint32 {.inline.} =
  return (x and y) xor (x and z) xor (y and z)


func majority(x, y, z: uint64): uint64 {.inline.} =
  return (x and y) xor (x and z) xor (y and z)


func sigma0(x: uint32): uint32 {.inline.} =
  return rotateRight(x, 7) xor rotateRight(x, 18) xor (x shr 3)


func sigma0(x: uint64): uint64 {.inline.} =
  return rotateRight(x, 1) xor rotateRight(x, 8) xor (x shr 7)


func sigma1(x: uint32): uint32 {.inline.} =
  return rotateRight(x, 17) xor rotateRight(x, 19) xor (x shr 10)


func sigma1(x: uint64): uint64 {.inline.} =
  return rotateRight(x, 19) xor rotateRight(x, 61) xor (x shr 6)


func Sigma0(x: uint32): uint32 {.inline.} =
  return rotateRight(x, 2) xor rotateRight(x, 13) xor rotateRight(x, 22)


func Sigma0(x: uint64): uint64 {.inline.} =
  return rotateRight(x, 28) xor rotateRight(x, 34) xor rotateRight(x, 39)


func Sigma1(x: uint32): uint32 {.inline.} =
  return rotateRight(x, 6) xor rotateRight(x, 11) xor rotateRight(x, 25)


func Sigma1(x: uint64): uint64 {.inline.} =
  return rotateRight(x, 14) xor rotateRight(x, 18) xor rotateRight(x, 41)
