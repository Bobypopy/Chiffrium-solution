Imports System.Security.Cryptography
Public Class Legacy
    Public Function Protect(data As Byte()) As Byte()
        Dim des As New TripleDESCryptoServiceProvider()
        Return SHA1.Create().ComputeHash(data)
    End Function
End Class
