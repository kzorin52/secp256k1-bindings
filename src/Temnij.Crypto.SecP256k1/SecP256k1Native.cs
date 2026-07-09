using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Temnij.Crypto;

// +s of some wrapper:
// + devs can use all power of libsecp256k1
// + argument length checking
// + idk, looks funny, maybe it really would be useful
// -s:
// - frequent length checks may slow down some loops code with constant arguments (?)
// ?s
// ? publicKey, signature, etc. as structs?
// - ? structs with corresponding methods?

/// <summary>
///     Low-level thin wrapper
/// </summary>
// ReSharper disable once InconsistentNaming
public static partial class SecP256k1Native
{
    private const string LibraryName = "secp256k1";

    public static nint Context;

    static SecP256k1Native()
    {
        SetLibraryFallbackResolver();
        Context = CreateContext(ContextFlags.None);

        Span<byte> seed = stackalloc byte[32];
        RandomNumberGenerator.Fill(seed);
        _ = secp256k1_context_randomize(Context, seed);
    }

    #region LIBRARY

    private static void SetLibraryFallbackResolver()
    {
        Assembly assembly = typeof(SecP256k1Native).Assembly;

        AssemblyLoadContext.GetLoadContext(assembly)!.ResolvingUnmanagedDll += (context, name) =>
        {
            if (context != assembly || !LibraryName.Equals(name, StringComparison.Ordinal))
                return nint.Zero;

            string platform;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                name = $"lib{name}.so";
                platform = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                name = $"lib{name}.dylib";
                platform = "osx";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                name = $"{name}.dll";
                platform = "win";
            }
            else
                throw new PlatformNotSupportedException();

            var arch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

            // Try looking in the runtimes folder (Portable publish / Dev environment).
            // Anchor to the assembly location: relative paths resolve against the process CWD,
            // which breaks under custom load contexts (e.g. test hosts).
            var assemblyDir = Path.GetDirectoryName(assembly.Location);
            if (!string.IsNullOrEmpty(assemblyDir))
            {
                var runtimesPath = Path.Combine(assemblyDir, "runtimes", $"{platform}-{arch}", "native", name);
                if (NativeLibrary.TryLoad(runtimesPath, out var handle))
                    return handle;
            }

            // Fallback to looking in the root directory (RID-specific publish, e.g. win-x64)
            return NativeLibrary.Load(name, context, DllImportSearchPath.AssemblyDirectory);
        };
    }

    #endregion

    #region LOW-LEVEL API

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetSerializedPublicKeySize(ECType type)
    {
        return type switch
        {
            ECType.Compressed => 33,
            ECType.Uncompressed => 65,
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }

    [Flags]
    public enum ContextFlags : uint
    {
        None = Secp256K1FlagsTypeContext,

        /// <summary>
        ///     Deprecated
        /// </summary>
        Verify = Secp256K1FlagsTypeContext | Secp256K1FlagsBitContextVerify,

        /// <summary>
        ///     Deprecated
        /// </summary>
        Sign = Secp256K1FlagsTypeContext | Secp256K1FlagsBitContextSign
    }

    public enum ECType : uint
    {
        Compressed = Secp256K1FlagsTypeCompression | Secp256K1FlagsBitCompression,
        Uncompressed = Secp256K1FlagsTypeCompression
    }

    public enum KeyType : byte
    {
        PrivateKey = 0,
        PublicKey = 1
    }

    public enum TweakMode : byte
    {
        Add = 0,
        Multiply = 1
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Selftest()
    {
        secp256k1_selftest();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static nint CreateContext(ContextFlags flags)
    {
        return secp256k1_context_create((uint)flags);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DestroyContext()
    {
        secp256k1_context_destroy(Context);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ParsePublicKey(Span<byte> raw, ReadOnlySpan<byte> serialized)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(raw.Length, PublicKeySize, nameof(raw));
        if (serialized.Length != 33 && serialized.Length != 65) throw new ArgumentException($"{nameof(serialized)} must be 33 or 65 bytes");

        return secp256k1_ec_pubkey_parse(Context, raw, serialized, (nuint)serialized.Length) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int SerializePublicKey(Span<byte> serialized, ReadOnlySpan<byte> publicKey, ECType type)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfNotEqual(serialized.Length, GetSerializedPublicKeySize(type), nameof(serialized));

        nuint outputSize = (nuint)serialized.Length;
        secp256k1_ec_pubkey_serialize(Context, serialized, ref outputSize, publicKey, (uint)type);

        return (int)outputSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ComparePublicKeys(ReadOnlySpan<byte> publicKey1, ReadOnlySpan<byte> publicKey2)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey1.Length, PublicKeySize, nameof(publicKey1));
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey2.Length, PublicKeySize, nameof(publicKey2));

        return secp256k1_ec_pubkey_cmp(Context, publicKey1, publicKey2);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ParseCompactSignature(Span<byte> signature, ReadOnlySpan<byte> compactSig)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));
        ArgumentOutOfRangeException.ThrowIfLessThan(compactSig.Length, CompactSignatureSize, nameof(compactSig));
        return secp256k1_ecdsa_signature_parse_compact(Context, signature, compactSig) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ParseDerSignature(Span<byte> signature, ReadOnlySpan<byte> raw)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));
        return secp256k1_ecdsa_signature_parse_der(Context, signature, raw, (nuint)raw.Length) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int SerializeDerSignature(Span<byte> output, ReadOnlySpan<byte> signature)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));

        var len = (nuint)output.Length;
        if (secp256k1_ecdsa_signature_serialize_der(Context, output, ref len, signature) == 0)
            return 0;

        return (int)len;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void SerializeCompactSignature(Span<byte> compactSig, ReadOnlySpan<byte> signature)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(compactSig.Length, CompactSignatureSize, nameof(compactSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));

        secp256k1_ecdsa_signature_serialize_compact(Context, compactSig, signature);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> msgHash, ReadOnlySpan<byte> publicKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));
        ArgumentOutOfRangeException.ThrowIfLessThan(msgHash.Length, 32, nameof(msgHash));
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));

        return secp256k1_ecdsa_verify(Context, signature, msgHash, publicKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int NormalizeSignature(Span<byte> outputSignature, ReadOnlySpan<byte> inputSignature)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(outputSignature.Length, SignatureSize, nameof(outputSignature));
        ArgumentOutOfRangeException.ThrowIfLessThan(inputSignature.Length, SignatureSize, nameof(inputSignature));

        return secp256k1_ecdsa_signature_normalize(Context, outputSignature, inputSignature);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Sign(Span<byte> signature, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> privateKey, nint nonceGenFunPtr = 0, nint nonceData = 0)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));
        ArgumentOutOfRangeException.ThrowIfLessThan(messageHash.Length, 32, nameof(messageHash));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        return secp256k1_ecdsa_sign(Context, signature, messageHash, privateKey, nonceGenFunPtr, nonceData) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool VerifyPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));
        return secp256k1_ec_seckey_verify(Context, privateKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool CreatePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        return secp256k1_ec_pubkey_create(Context, publicKey, privateKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool NegatePrivateKey(Span<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));
        return secp256k1_ec_seckey_negate(Context, privateKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool NegatePublicKey(Span<byte> publicKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        return secp256k1_ec_pubkey_negate(Context, publicKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Tweak(Span<byte> key, ReadOnlySpan<byte> tweak, KeyType type, TweakMode mode)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(tweak.Length, 32, nameof(tweak));
        ArgumentOutOfRangeException.ThrowIfLessThan(key.Length,
            type == KeyType.PrivateKey ? PrivateKeySize : PublicKeySize, nameof(key));

        return mode switch
        {
            TweakMode.Add => type switch
            {
                KeyType.PrivateKey => secp256k1_ec_seckey_tweak_add(Context, key, tweak),
                KeyType.PublicKey => secp256k1_ec_pubkey_tweak_add(Context, key, tweak),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            },
            TweakMode.Multiply => type switch
            {
                KeyType.PrivateKey => secp256k1_ec_seckey_tweak_mul(Context, key, tweak),
                KeyType.PublicKey => secp256k1_ec_pubkey_tweak_mul(Context, key, tweak),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            },
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
        } == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void TaggedSHA256(Span<byte> output, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, 32, nameof(output));
        secp256k1_tagged_sha256(Context, output, tag, (nuint)tag.Length, message, (nuint)message.Length);
    }

    /// <summary>
    ///     ECDH whose "hash" is simply the raw X coordinate of the shared point (first 32 bytes of
    ///     <paramref name="output" />). Allocation- and marshaling-free, unlike the delegate-based overload.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe bool ECDHRawX(Span<byte> output, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, 32, nameof(output));
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        return secp256k1_ecdh(Context, output, publicKey, privateKey,
            (nint)(delegate* unmanaged[Cdecl]<void*, void*, void*, nint, int>)&CopyXCallback, 0) == 1;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static unsafe int CopyXCallback(void* output, void* x32, void* y32, nint data)
    {
        Unsafe.CopyBlockUnaligned(output, x32, 32);
        return 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ECDH(Span<byte> output, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, secp256k1_ecdh_hash_function? hashFunction, nint data = 0)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        if (hashFunction == null) return secp256k1_ecdh(Context, output, publicKey, privateKey, 0, data) == 1;

        var gch = GCHandle.Alloc(hashFunction);
        try
        {
            var fp = Marshal.GetFunctionPointerForDelegate(hashFunction);
            return secp256k1_ecdh(Context, output, publicKey, privateKey, fp, data) == 1;
        }
        finally
        {
            gch.Free();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ParseRecoverableCompactSignature(Span<byte> recoverableSig, ReadOnlySpan<byte> compactSig, int recoveryId)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recoverableSig.Length, RecoverableSignatureSize, nameof(recoverableSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(compactSig.Length, CompactSignatureSize, nameof(compactSig));
        return secp256k1_ecdsa_recoverable_signature_parse_compact(Context, recoverableSig, compactSig, recoveryId) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ConvertRecoverableSignature(Span<byte> signature, ReadOnlySpan<byte> recoverableSig)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recoverableSig.Length, RecoverableSignatureSize, nameof(recoverableSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, SignatureSize, nameof(signature));
        secp256k1_ecdsa_recoverable_signature_convert(Context, signature, recoverableSig);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void SerializeRecoverableCompactSignature(Span<byte> compactSig, ReadOnlySpan<byte> recoverableSig, out int recoveryId)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recoverableSig.Length, RecoverableSignatureSize, nameof(recoverableSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(compactSig.Length, CompactSignatureSize, nameof(compactSig));
        secp256k1_ecdsa_recoverable_signature_serialize_compact(Context, compactSig, out recoveryId, recoverableSig);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool SignRecoverable(Span<byte> recoverableSig, ReadOnlySpan<byte> msgHash, ReadOnlySpan<byte> privateKey, nint nonceGenFunPtr = 0, nint nonceData = 0)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recoverableSig.Length, RecoverableSignatureSize, nameof(recoverableSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(msgHash.Length, 32, nameof(msgHash));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        return secp256k1_ecdsa_sign_recoverable(Context, recoverableSig, msgHash, privateKey, nonceGenFunPtr, nonceData) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Recover(Span<byte> publicKey, ReadOnlySpan<byte> recoverableSig, ReadOnlySpan<byte> messageHash)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recoverableSig.Length, RecoverableSignatureSize, nameof(recoverableSig));
        ArgumentOutOfRangeException.ThrowIfLessThan(messageHash.Length, 32, nameof(messageHash));
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));

        return secp256k1_ecdsa_recover(Context, publicKey, recoverableSig, messageHash) == 1;
    }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ParseXOnlyPublicKey(Span<byte> xOnlyPubkey, ReadOnlySpan<byte> serialized32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey));
        ArgumentOutOfRangeException.ThrowIfLessThan(serialized32.Length, 32, nameof(serialized32));

        return secp256k1_xonly_pubkey_parse(Context, xOnlyPubkey, serialized32) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void SerializeXOnlyPublicKey(Span<byte> serialized32, ReadOnlySpan<byte> xOnlyPubkey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(serialized32.Length, 32, nameof(serialized32));
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey));

        secp256k1_xonly_pubkey_serialize(Context, serialized32, xOnlyPubkey);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int CompareXOnlyPublicKeys(ReadOnlySpan<byte> xOnlyPubkey1, ReadOnlySpan<byte> xOnlyPubkey2)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey1.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey1));
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey2.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey2));

        return secp256k1_xonly_pubkey_cmp(Context, xOnlyPubkey1, xOnlyPubkey2);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ConvertPublicKeyToXOnly(Span<byte> xOnlyPubkey, out int pkParity, ReadOnlySpan<byte> pubkey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey));
        ArgumentOutOfRangeException.ThrowIfLessThan(pubkey.Length, PublicKeySize, nameof(pubkey));

        return secp256k1_xonly_pubkey_from_pubkey(Context, xOnlyPubkey, out pkParity, pubkey) == 1;
    }

    /// <summary>
    /// Tweaks an x-only public key. Returns a normal public key (not x-only).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool XOnlyTweakAdd(Span<byte> publicKey, ReadOnlySpan<byte> xOnlyPubkey, ReadOnlySpan<byte> tweak)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey));
        ArgumentOutOfRangeException.ThrowIfLessThan(tweak.Length, 32, nameof(tweak));

        return secp256k1_xonly_pubkey_tweak_add(Context, publicKey, xOnlyPubkey, tweak) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool CheckXOnlyTweakAdd(ReadOnlySpan<byte> tweakedPubkey32, int tweakedPkParity, ReadOnlySpan<byte> internalXOnlyPubkey, ReadOnlySpan<byte> tweak)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(tweakedPubkey32.Length, 32, nameof(tweakedPubkey32));
        ArgumentOutOfRangeException.ThrowIfLessThan(internalXOnlyPubkey.Length, XOnlyPublicKeySize, nameof(internalXOnlyPubkey));
        ArgumentOutOfRangeException.ThrowIfLessThan(tweak.Length, 32, nameof(tweak));

        return secp256k1_xonly_pubkey_tweak_add_check(Context, tweakedPubkey32, tweakedPkParity, internalXOnlyPubkey, tweak) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool CreateKeyPair(Span<byte> keyPair, ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keyPair.Length, KeyPairSize, nameof(keyPair));
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));

        return secp256k1_keypair_create(Context, keyPair, privateKey) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool GetSecretFromKeyPair(Span<byte> privateKey, ReadOnlySpan<byte> keyPair)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(privateKey.Length, PrivateKeySize, nameof(privateKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(keyPair.Length, KeyPairSize, nameof(keyPair));

        return secp256k1_keypair_sec(Context, privateKey, keyPair) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool GetPublicKeyFromKeyPair(Span<byte> publicKey, ReadOnlySpan<byte> keyPair)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfLessThan(keyPair.Length, KeyPairSize, nameof(keyPair));

        return secp256k1_keypair_pub(Context, publicKey, keyPair) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool GetXOnlyPublicKeyFromKeyPair(Span<byte> xOnlyPubkey, out int pkParity, ReadOnlySpan<byte> keyPair)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(xOnlyPubkey.Length, XOnlyPublicKeySize, nameof(xOnlyPubkey));
        ArgumentOutOfRangeException.ThrowIfLessThan(keyPair.Length, KeyPairSize, nameof(keyPair));

        return secp256k1_keypair_xonly_pub(Context, xOnlyPubkey, out pkParity, keyPair) == 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool XOnlyTweakKeyPair(Span<byte> keyPair, ReadOnlySpan<byte> tweak)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keyPair.Length, KeyPairSize, nameof(keyPair));
        ArgumentOutOfRangeException.ThrowIfLessThan(tweak.Length, 32, nameof(tweak));

        return secp256k1_keypair_xonly_tweak_add(Context, keyPair, tweak) == 1;
    }

    #endregion

    #region FLAG CONSTANTS

    private const uint Secp256K1FlagsTypeMask = (1 << 8) - 1;
    private const uint Secp256K1FlagsTypeContext = 1 << 0;
    private const uint Secp256K1FlagsTypeCompression = 1 << 1;

    /* The higher bits contain the actual data. Do not use directly. */
    private const uint Secp256K1FlagsBitContextVerify = 1 << 8;
    private const uint Secp256K1FlagsBitContextSign = 1 << 9;
    private const uint Secp256K1FlagsBitCompression = 1 << 8;

    public const uint Secp256K1TagPubkeyEven = 0x02;
    public const uint Secp256K1TagPubkeyOdd = 0x03;
    public const uint Secp256K1TagPubkeyUncompressed = 0x04;
    public const uint Secp256K1TagPubkeyHybridEven = 0x06;
    public const uint Secp256K1TagPubkeyHybridOdd = 0x07;

    public const int PublicKeySize = 64;
    public const int PrivateKeySize = 32;
    public const int SignatureSize = 64;
    public const int CompactSignatureSize = 64;
    public const int RecoverableSignatureSize = 65;

    public const int XOnlyPublicKeySize = 64; // Internal opaque struct size
    public const int KeyPairSize = 96;        // Internal opaque struct size

    #endregion

    #region NATIVE

    // ReSharper disable InconsistentNaming
    public unsafe delegate int secp256k1_ecdh_hash_function(void* output, void* x32, void* y32, nint data);
    // ReSharper restore InconsistentNaming

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_selftest();

    [LibraryImport(LibraryName)]
    private static partial nint secp256k1_context_create(uint flags);

    [LibraryImport(LibraryName)]
    private static partial nint secp256k1_context_clone(nint ctx);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_context_destroy(nint ctx);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_parse(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> input, nuint inputlen);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_ec_pubkey_serialize(nint ctx, Span<byte> output, ref nuint outputlen, ReadOnlySpan<byte> pubkey, uint flags);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_cmp(nint ctx, ReadOnlySpan<byte> pubkey1, ReadOnlySpan<byte> pubkey2);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_signature_parse_compact(nint ctx, Span<byte> sig, ReadOnlySpan<byte> input64);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_signature_parse_der(nint ctx, Span<byte> sig, ReadOnlySpan<byte> input, nuint inputlen);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_signature_serialize_der(nint ctx, Span<byte> output, ref nuint outputLen, ReadOnlySpan<byte> sig);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_ecdsa_signature_serialize_compact(IntPtr ctx, Span<byte> output64, ReadOnlySpan<byte> sig);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_verify(nint ctx, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> msghash32, ReadOnlySpan<byte> pubkey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_signature_normalize(nint ctx, Span<byte> sigout, ReadOnlySpan<byte> sigin);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_sign(nint ctx, Span<byte> sig, ReadOnlySpan<byte> msghash32, ReadOnlySpan<byte> seckey, nint noncefp, nint ndata);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_seckey_verify(nint ctx, ReadOnlySpan<byte> seckey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_create(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> seckey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_seckey_negate(nint ctx, Span<byte> seckey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_negate(nint ctx, Span<byte> pubkey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_seckey_tweak_add(nint ctx, Span<byte> seckey, ReadOnlySpan<byte> tweak32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_tweak_add(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> tweak32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_seckey_tweak_mul(nint ctx, Span<byte> seckey, ReadOnlySpan<byte> tweak32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ec_pubkey_tweak_mul(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> tweak32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_context_randomize(nint ctx, Span<byte> seed32);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_tagged_sha256(IntPtr ctx, Span<byte> hash32, ReadOnlySpan<byte> tag, UIntPtr taglen, ReadOnlySpan<byte> msg, UIntPtr msglen);

    /* ecdh */

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdh(nint ctx, Span<byte> output, ReadOnlySpan<byte> pubkey, ReadOnlySpan<byte> seckey, nint hashfp, nint data);

    /* recovery */

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_recoverable_signature_parse_compact(nint ctx, Span<byte> sig, ReadOnlySpan<byte> input64, int recid);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_ecdsa_recoverable_signature_convert(IntPtr ctx, Span<byte> sig, ReadOnlySpan<byte> sigin);

    [LibraryImport(LibraryName)]
    private static partial void secp256k1_ecdsa_recoverable_signature_serialize_compact(IntPtr ctx, Span<byte> output64, out int recid, ReadOnlySpan<byte> signature);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_sign_recoverable(nint ctx, Span<byte> sig, ReadOnlySpan<byte> msghash32, ReadOnlySpan<byte> seckey, nint noncefp, nint ndata);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_ecdsa_recover(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> msghash32);

    /* xonly */

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_parse(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> input32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_serialize(nint ctx, Span<byte> output32, ReadOnlySpan<byte> pubkey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_cmp(nint ctx, ReadOnlySpan<byte> pk1, ReadOnlySpan<byte> pk2);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_from_pubkey(nint ctx, Span<byte> xonlyPubkey, out int pkParity, ReadOnlySpan<byte> pubkey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_tweak_add(nint ctx, Span<byte> outputPubkey, ReadOnlySpan<byte> internalPubkey, ReadOnlySpan<byte> tweak);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_xonly_pubkey_tweak_add_check(nint ctx, ReadOnlySpan<byte> tweakedPubkey32, int tweakedPkParity, ReadOnlySpan<byte> internalPubkey, ReadOnlySpan<byte> tweak32);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_keypair_create(nint ctx, Span<byte> keypair, ReadOnlySpan<byte> seckey);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_keypair_sec(nint ctx, Span<byte> seckey, ReadOnlySpan<byte> keypair);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_keypair_pub(nint ctx, Span<byte> pubkey, ReadOnlySpan<byte> keypair);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_keypair_xonly_pub(nint ctx, Span<byte> pubkey, out int pkParity, ReadOnlySpan<byte> keypair);

    [LibraryImport(LibraryName)]
    private static partial int secp256k1_keypair_xonly_tweak_add(nint ctx, Span<byte> keypair, ReadOnlySpan<byte> tweak32);

    #endregion

    // TODO: Callbacks[?], Ellswift, MuSig, Schnorr signatures
    // currently can't implement secp256k1_ec_pubkey_sort and secp256k1_ec_pubkey_combine because of c# Span<T> limitations.
}
