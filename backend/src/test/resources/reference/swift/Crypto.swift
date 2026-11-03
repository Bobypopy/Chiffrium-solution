import CryptoKit

func legacy(data: Data) -> Insecure.MD5.Digest { Insecure.MD5.hash(data: data) }
func seal(data: Data, key: SymmetricKey) throws -> AES.GCM.SealedBox { try AES.GCM.seal(data, using: key) }
