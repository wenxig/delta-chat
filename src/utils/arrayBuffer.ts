export const processStringArray = (buf: ArrayBufferLike, fn: (str: string) => string) =>
  new TextEncoder().encode(fn(new TextDecoder().decode(buf))).buffer