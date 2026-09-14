// ─────────────────────────────────────────────────────────────────────────────
// Compatibility layer for .NET Framework 4.8 / Windows 10 & 11 Native Runtime
// ─────────────────────────────────────────────────────────────────────────────
global using System;
global using System.Collections.Generic;
global using System.Diagnostics;
global using System.Drawing;
global using System.IO;
global using System.Linq;
global using System.Net.Http;
global using System.Security.Cryptography;
global using System.Text;
global using System.Threading;
global using System.Threading.Tasks;
global using System.Windows.Forms;
global using ACS;

namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}

namespace System
{
    public readonly struct Index : IEquatable<Index>
    {
        private readonly int _value;
        public Index(int value, bool fromEnd = false)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value), "value must be non-negative");
            _value = fromEnd ? ~value : value;
        }
        public static Index Start => new Index(0);
        public static Index End => new Index(~0);
        public static Index FromStart(int value) => new Index(value);
        public static Index FromEnd(int value) => new Index(value, true);
        public int Value => _value < 0 ? ~_value : _value;
        public bool IsFromEnd => _value < 0;
        public int GetOffset(int length) => IsFromEnd ? length - (~_value) : _value;
        public override bool Equals(object? value) => value is Index && _value == ((Index)value)._value;
        public bool Equals(Index other) => _value == other._value;
        public override int GetHashCode() => _value;
        public static implicit operator Index(int value) => FromStart(value);
        public override string ToString() => IsFromEnd ? "^" + Value.ToString() : Value.ToString();
    }

    public readonly struct Range : IEquatable<Range>
    {
        public Index Start { get; }
        public Index End { get; }
        public Range(Index start, Index end) { Start = start; End = end; }
        public override bool Equals(object? value) => value is Range r && r.Start.Equals(Start) && r.End.Equals(End);
        public bool Equals(Range other) => other.Start.Equals(Start) && other.End.Equals(End);
        public override int GetHashCode() => Start.GetHashCode() * 31 + End.GetHashCode();
        public override string ToString() => $"{Start}..{End}";
        public static Range StartAt(Index start) => new Range(start, Index.End);
        public static Range EndAt(Index end) => new Range(Index.Start, end);
        public static Range All => new Range(Index.Start, Index.End);
        public (int Offset, int Length) GetOffsetAndLength(int length)
        {
            int start = Start.GetOffset(length);
            int end = End.GetOffset(length);
            if ((uint)end > (uint)length || (uint)start > (uint)end)
                throw new ArgumentOutOfRangeException();
            return (start, end - start);
        }
    }
}

namespace System.Collections.Generic
{
    public static class DictionaryExtensions
    {
        public static TValue GetValueOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue = default!)
        {
            if (dictionary != null && dictionary.TryGetValue(key, out var val))
                return val;
            return defaultValue;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue = default!)
        {
            if (dictionary != null && dictionary.TryGetValue(key, out var val))
                return val;
            return defaultValue;
        }
    }

    public static class KeyValuePairExtensions
    {
        public static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> pair, out TKey key, out TValue value)
        {
            key = pair.Key;
            value = pair.Value;
        }
    }
}

namespace System.Text
{
    public static class EncodingExtensions
    {
        public static string GetString(this Encoding encoding, ReadOnlySpan<byte> bytes)
        {
            return encoding.GetString(bytes.ToArray());
        }

        public static string GetString(this Encoding encoding, Span<byte> bytes)
        {
            return encoding.GetString(bytes.ToArray());
        }
    }
}

namespace ACS
{
    public static class HttpExtensions
    {
        public static async Task<string> GetStringAsync(this HttpClient client, string requestUri, CancellationToken cancellationToken)
        {
            using (var response = await client.GetAsync(requestUri, cancellationToken).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }

        public static Task<string> ReadAsStringAsync(this HttpContent content, CancellationToken cancellationToken)
        {
            return content.ReadAsStringAsync();
        }
    }

    public static class StringExtensions
    {
        public static string[] Split(this string str, char separator, StringSplitOptions options = StringSplitOptions.None)
        {
            if (str == null) return Array.Empty<string>();
            return str.Split(new[] { separator }, options);
        }

        public static bool Contains(this string str, string value, StringComparison comparisonType)
        {
            if (str == null || value == null) return false;
            return str.IndexOf(value, comparisonType) >= 0;
        }

        public static bool Contains(this string str, char value)
        {
            if (str == null) return false;
            return str.IndexOf(value) >= 0;
        }

        public static string Replace(this string str, string oldValue, string newValue, StringComparison comparisonType)
        {
            if (string.IsNullOrEmpty(str) || string.IsNullOrEmpty(oldValue)) return str;
            int idx = str.IndexOf(oldValue, comparisonType);
            if (idx < 0) return str;
            StringBuilder sb = new StringBuilder();
            int prev = 0;
            while (idx >= 0)
            {
                sb.Append(str, prev, idx - prev);
                sb.Append(newValue);
                prev = idx + oldValue.Length;
                idx = str.IndexOf(oldValue, prev, comparisonType);
            }
            sb.Append(str, prev, str.Length - prev);
            return sb.ToString();
        }

        public static string ReplaceOrdinalIgnoreCase(this string str, string oldValue, string newValue)
        {
            return Replace(str, oldValue, newValue, StringComparison.OrdinalIgnoreCase);
        }

        // Enables string[Range] on .NET Framework 4.8
        public static string Substring(this string str, Range range)
        {
            if (str == null) throw new ArgumentNullException(nameof(str));
            var (offset, length) = range.GetOffsetAndLength(str.Length);
            return str.Substring(offset, length);
        }
    }

    public static class MathUtils
    {
        public static int Clamp(int value, int min, int max) => Math.Min(Math.Max(value, min), max);
        public static float Clamp(float value, float min, float max) => Math.Min(Math.Max(value, min), max);
        public static double Clamp(double value, double min, double max) => Math.Min(Math.Max(value, min), max);
    }

    public static class PathUtils
    {
        public static string GetRelativePath(string relativeTo, string path)
        {
            if (string.IsNullOrEmpty(relativeTo)) return path;
            if (string.IsNullOrEmpty(path)) return "";

            try
            {
                string fromPath = Path.GetFullPath(relativeTo);
                string toPath = Path.GetFullPath(path);

                if (toPath.StartsWith(fromPath, StringComparison.OrdinalIgnoreCase))
                {
                    string rel = toPath.Substring(fromPath.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    return string.IsNullOrEmpty(rel) ? "." : rel;
                }

                Uri fromUri = new Uri(AppendDirectorySeparator(fromPath));
                Uri toUri = new Uri(toPath);

                if (fromUri.Scheme != toUri.Scheme) return path;

                Uri relativeUri = fromUri.MakeRelativeUri(toUri);
                string relativePath = Uri.UnescapeDataString(relativeUri.ToString());

                if (toUri.Scheme.Equals("file", StringComparison.OrdinalIgnoreCase))
                {
                    relativePath = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
                }

                return relativePath;
            }
            catch
            {
                return path;
            }
        }

        private static string AppendDirectorySeparator(string path)
        {
            if (!path.EndsWith(Path.DirectorySeparatorChar.ToString()) && !path.EndsWith(Path.AltDirectorySeparatorChar.ToString()))
            {
                return path + Path.DirectorySeparatorChar;
            }
            return path;
        }
    }

    public static class CryptoUtils
    {
        public static string ToHex(byte[]? bytes)
        {
            if (bytes == null || bytes.Length == 0) return "";
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string Sha256Hex(byte[] bytes)
        {
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(bytes));
        }

        public static string Sha256Hex(Stream stream)
        {
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(stream));
        }

        public static string Sha1Hex(byte[] bytes)
        {
            using (var sha = SHA1.Create())
                return ToHex(sha.ComputeHash(bytes));
        }

        public static string Md5Hex(byte[] bytes)
        {
            using (var md5 = MD5.Create())
                return ToHex(md5.ComputeHash(bytes));
        }
    }
}
