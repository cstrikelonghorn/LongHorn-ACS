namespace ACPScanner;

public sealed record ScanUploadResult(
    bool Uploaded,
    string Status,
    int Detected,
    int Warnings,
    int Processes,
    int Drivers,
    int HlFiles,
    string? ReportUrl,
    string? Error,
    bool UploadDeclined = false);
