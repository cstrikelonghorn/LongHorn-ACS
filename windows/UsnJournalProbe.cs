using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace ACPScanner;

internal static class UsnJournalProbe
{
    internal sealed record DeletedFileRecord(string FileName, DateTimeOffset DeletedAt, string Volume);

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FsctlQueryUsnJournal = 0x000900f4;
    private const uint FsctlReadUsnJournal = 0x000900bb;
    private const uint UsnReasonFileDelete = 0x00000200;

    [StructLayout(LayoutKind.Sequential)]
    private struct UsnJournalDataV0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ReadUsnJournalDataV0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll", ".exe", ".asi", ".sys", ".drv"
    };

    public static List<DeletedFileRecord> ScanRecentDeletions(string rootPath, TimeSpan threshold, out string? note)
    {
        note = null;
        var results = new List<DeletedFileRecord>();
        try
        {
            var drive = Path.GetPathRoot(Path.GetFullPath(rootPath))?.TrimEnd('\\');
            if (string.IsNullOrWhiteSpace(drive))
            {
                drive = "C:";
            }

            var volumePath = $@"\\.\{drive}";
            var hVolume = CreateFile(
                volumePath,
                GenericRead,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);

            if (hVolume == IntPtr.Zero || hVolume == new IntPtr(-1))
            {
                note = "NTFS USN Change Journal inspection requires Administrator privileges.";
                return results;
            }

            try
            {
                var queryBufferSize = Marshal.SizeOf<UsnJournalDataV0>();
                var queryBuffer = Marshal.AllocHGlobal(queryBufferSize);
                try
                {
                    if (!DeviceIoControl(hVolume, FsctlQueryUsnJournal, IntPtr.Zero, 0, queryBuffer, (uint)queryBufferSize, out _, IntPtr.Zero))
                    {
                        note = "Volume does not support NTFS USN Journal or access was denied.";
                        return results;
                    }

                    var journalData = Marshal.PtrToStructure<UsnJournalDataV0>(queryBuffer);

                    var readData = new ReadUsnJournalDataV0
                    {
                        StartUsn = Math.Max(journalData.LowestValidUsn, journalData.NextUsn - (1024 * 1024 * 4)),
                        ReasonMask = UsnReasonFileDelete,
                        ReturnOnlyOnClose = 0,
                        Timeout = 0,
                        BytesToWaitFor = 0,
                        UsnJournalID = journalData.UsnJournalID
                    };

                    int bufferSize = 64 * 1024;
                    var readBuffer = Marshal.AllocHGlobal(bufferSize);
                    var inputBufferSize = Marshal.SizeOf<ReadUsnJournalDataV0>();
                    var inputBuffer = Marshal.AllocHGlobal(inputBufferSize);

                    try
                    {
                        Marshal.StructureToPtr(readData, inputBuffer, false);
                        var cutoff = DateTimeOffset.UtcNow - threshold;

                        if (DeviceIoControl(hVolume, FsctlReadUsnJournal, inputBuffer, (uint)inputBufferSize, readBuffer, (uint)bufferSize, out uint bytesReturned, IntPtr.Zero))
                        {
                            if (bytesReturned > 8)
                            {
                                int offset = 8; // skip NextUsn field
                                while (offset < bytesReturned)
                                {
                                    int recordLength = Marshal.ReadInt32(readBuffer, offset);
                                    if (recordLength <= 0) break;

                                    ushort majorVersion = (ushort)Marshal.ReadInt16(readBuffer, offset + 4);
                                    if (majorVersion == 2)
                                    {
                                        long timeStamp = Marshal.ReadInt64(readBuffer, offset + 32);
                                        uint reason = (uint)Marshal.ReadInt32(readBuffer, offset + 40);
                                        ushort fileNameLen = (ushort)Marshal.ReadInt16(readBuffer, offset + 56);
                                        ushort fileNameOffset = (ushort)Marshal.ReadInt16(readBuffer, offset + 58);

                                        if ((reason & UsnReasonFileDelete) != 0 && fileNameLen > 0)
                                        {
                                            var deletedTime = DateTimeOffset.FromFileTime(timeStamp);
                                            if (deletedTime >= cutoff)
                                            {
                                                IntPtr namePtr = IntPtr.Add(readBuffer, offset + fileNameOffset);
                                                string fileName = Marshal.PtrToStringUni(namePtr, fileNameLen / 2) ?? "";
                                                var ext = Path.GetExtension(fileName);
                                                if (SuspiciousExtensions.Contains(ext))
                                                {
                                                    results.Add(new DeletedFileRecord(fileName, deletedTime, drive));
                                                }
                                            }
                                        }
                                    }
                                    offset += recordLength;
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(inputBuffer);
                        Marshal.FreeHGlobal(readBuffer);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(queryBuffer);
                }
            }
            finally
            {
                CloseHandle(hVolume);
            }
        }
        catch (Exception ex)
        {
            note = $"USN Journal probe failed: {ex.Message}";
        }

        return results;
    }
}
