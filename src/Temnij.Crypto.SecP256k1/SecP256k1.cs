using System;
using System.Runtime.CompilerServices;

// ReSharper disable once CheckNamespace
namespace Temnij.Crypto;

// ReSharper disable once InconsistentNaming
public static class SecP256k1
{
    public static bool GetPublicKey(Span<byte> serializedPublicKey, ReadOnlySpan<byte> privateKey, SecP256k1Native.ECType type)
    {
        Span<byte> publicKey = stackalloc byte[SecP256k1Native.PublicKeySize];
        if (!SecP256k1Native.CreatePublicKey(publicKey, privateKey)) return false;
        SecP256k1Native.SerializePublicKey(serializedPublicKey, publicKey, type);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[]? GetPublicKey(ReadOnlySpan<byte> privateKey, SecP256k1Native.ECType type) // Compatable with old API
    {
        var buffer = new byte[SecP256k1Native.GetSerializedPublicKeySize(type)];

        return GetPublicKey(buffer, privateKey, type)
            ? buffer
            : null;
    }

    public static bool SignCompact(Span<byte> compactSignature, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, out int recoveryId)
    {
        Span<byte> recoverableSignature = stackalloc byte[SecP256k1Native.RecoverableSignatureSize];
        recoveryId = 0;

        if (!SecP256k1Native.SignRecoverable(recoverableSignature, messageHash, privateKey)) return false;
        SecP256k1Native.SerializeRecoverableCompactSignature(compactSignature, recoverableSignature, out recoveryId);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[]? SignCompact(ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, out int recoveryId) // Compatable with old API
    {
        var buffer = new byte[SecP256k1Native.CompactSignatureSize];
        recoveryId = 0;

        return SignCompact(buffer, messageHash, privateKey, out recoveryId)
            ? buffer
            : null;
    }

    public static bool RecoverKeyFromCompact(Span<byte> output, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> compactSignature, int recoveryId, SecP256k1Native.ECType type)
    {
        Span<byte> recoverableSignature = stackalloc byte[SecP256k1Native.RecoverableSignatureSize];
        Span<byte> publicKey = stackalloc byte[SecP256k1Native.PublicKeySize];

        var expectedLength = SecP256k1Native.GetSerializedPublicKeySize(type);
        if (output.Length != expectedLength) throw new ArgumentException($"{nameof(output)} length should be {expectedLength}");

        if (!SecP256k1Native.ParseRecoverableCompactSignature(recoverableSignature, compactSignature, recoveryId)) return false;
        if (!SecP256k1Native.Recover(publicKey, recoverableSignature, messageHash)) return false;
        SecP256k1Native.SerializePublicKey(output, publicKey, type);

        return true;
    }

    public static unsafe bool Ecdh(Span<byte> agreement, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        var outputLength = agreement.Length;
        return SecP256k1Native.ECDH(agreement, publicKey, privateKey, HashFunction);

        // TODO: should probably do that only once
        int HashFunction(void* output, void* x, void* _, IntPtr __)
        {
            Span<byte> outputSpan = new(output, outputLength);
            Span<byte> xSpan = new(x, 32);
            xSpan.CopyTo(outputSpan);

            return 1;
        }
    }

    public static bool EcdhSerialized(Span<byte> output, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Span<byte> key = stackalloc byte[64];
        Span<byte> uncompressedPrefixedPublicKey = stackalloc byte[65];
        uncompressedPrefixedPublicKey[0] = 4;
        publicKey.CopyTo(uncompressedPrefixedPublicKey[1..]);

        if (!SecP256k1Native.ParsePublicKey(key, uncompressedPrefixedPublicKey)) return false;
        Ecdh(output, key, privateKey);

        return true;
    }

    public static byte[]? EcdhSerialized(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        var buffer = new byte[32];

        return EcdhSerialized(buffer, publicKey, privateKey)
            ? buffer
            : null;
    }

    public static bool Decompress(Span<byte> decompressed, ReadOnlySpan<byte> compressed)
    {
        Span<byte> publicKey = stackalloc byte[64];
        if (!SecP256k1Native.ParsePublicKey(publicKey, compressed)) return false;

        SecP256k1Native.SerializePublicKey(decompressed, publicKey, SecP256k1Native.ECType.Uncompressed);
        return true;
    }

    public static byte[]? Decompress(ReadOnlySpan<byte> compressed) // Compatable with old API
    {
        var buffer = new byte[65];
        return Decompress(buffer, compressed)
            ? buffer
            : null;
    }
}
