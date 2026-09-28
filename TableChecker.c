#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TableChecker.exe.c - PE Import Table Scanner
 *
 * Compile (MSVC):  cl TableChecker.exe.c
 * Compile (MinGW): gcc TableChecker.exe.c -o TableChecker.exe.exe
 *
 * Usage:
 *   TableChecker.exe -f <file>               scan a single file
 *   TableChecker.exe -d <dir>                scan all .sys files in a directory
 *   TableChecker.exe -r, --recurse           also scan subdirectories recursively
 *   TableChecker.exe -t <name> [name...]     match specific function names (exact)
 *   TableChecker.exe -l <listfile>           load target names from a text file
 *   TableChecker.exe --all                   dump every import, no filtering
 *   TableChecker.exe --prefix                treat -t values as prefixes (e.g. Zw, Mm)
 *   TableChecker.exe -v, --verbose           print directories and files being scanned
 *
 * Examples:
 *   TableChecker.exe -f eneio64.sys -t ZwTerminateProcess MmMapIoSpace
 *   TableChecker.exe -d C:\Windows\System32\drivers -r --prefix -t Zw Mm Ps Ob
 *   TableChecker.exe -d C:\tools\drivers -r -l targets.txt
 *   TableChecker.exe -f mystery.sys --all
 *   TableChecker.exe -d C:\drivers -r -v --all
 *
 * Output: tab-separated (file, module, function). Redirect to .tsv for Excel.
 */

/* Global verbose flag — easier than threading it through every call */
static int g_verbose = 0;


/* -------------------------------------------------------------------------
 * StripTrailingSlash
 * Removes a trailing backslash from a path in-place, unless it is a root
 * path like "C:\". Prevents double-backslash in FindFirstFile patterns.
 * ------------------------------------------------------------------------- */
void StripTrailingSlash(char* path)
{
    size_t len = strlen(path);
    if (len > 3 && (path[len - 1] == '\\' || path[len - 1] == '/'))
        path[len - 1] = '\0';
}


/* -------------------------------------------------------------------------
 * RvaToFileOffset
 * Converts a Relative Virtual Address to a file offset by walking the
 * section header table. Returns 0 if the RVA falls in no section.
 * ------------------------------------------------------------------------- */
DWORD RvaToFileOffset(BYTE* base, IMAGE_NT_HEADERS64* ntHeaders, DWORD rva)
{
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD secVA   = sections[i].VirtualAddress;
        DWORD secSize = sections[i].Misc.VirtualSize;

        if (rva >= secVA && rva < secVA + secSize)
            return sections[i].PointerToRawData + (rva - secVA);
    }
    return 0;
}


/* -------------------------------------------------------------------------
 * LoadFileToBuffer
 * Reads an entire file into a heap-allocated buffer.
 * Sets *outSize on success. Caller must free() the returned pointer.
 * Returns NULL on any failure.
 * ------------------------------------------------------------------------- */
BYTE* LoadFileToBuffer(const char* path, DWORD* outSize)
{
    HANDLE hFile = CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead = 0;
    ReadFile(hFile, buf, size, &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead != size) { free(buf); return NULL; }

    *outSize = size;
    return buf;
}


/* -------------------------------------------------------------------------
 * GetNtHeaders64
 * Validates the MZ and PE signatures and the 64-bit optional header magic.
 * Returns a pointer into the buffer cast to IMAGE_NT_HEADERS64*, or NULL
 * if the file is not a valid 64-bit PE (silently skipped by callers).
 * ------------------------------------------------------------------------- */
IMAGE_NT_HEADERS64* GetNtHeaders64(BYTE* base, DWORD fileSize)
{
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    if (dos->e_lfanew <= 0 ||
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize)
        return NULL;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return NULL;

    return nt;
}


/* -------------------------------------------------------------------------
 * CheckMatch
 * Compares a resolved function name against the target list and prints hits.
 * targetCount == 0 means dump-all mode (no filtering).
 * prefixMode uses strnicmp so "-t Zw" matches any Zw* function.
 * ------------------------------------------------------------------------- */
void CheckMatch(
    const char* filename,
    const char* moduleName,
    const char* funcName,
    char**       targets,
    int          targetCount,
    int          prefixMode)
{
    if (targetCount == 0) {
        printf("%s\t%s\t%s\n", filename, moduleName, funcName);
        return;
    }

    for (int i = 0; i < targetCount; i++) {
        int matched = 0;

        if (prefixMode)
            matched = (_strnicmp(funcName, targets[i], strlen(targets[i])) == 0);
        else
            matched = (_stricmp(funcName, targets[i]) == 0);

        if (matched) {
            printf("[MATCH]\t%s\t%s\t%s\n", filename, moduleName, funcName);
            return;
        }
    }
}


/* -------------------------------------------------------------------------
 * WalkThunks
 * Walks the OriginalFirstThunk array for one imported module.
 * Skips ordinal-only imports (no name string available).
 * Resolves each named thunk to IMAGE_IMPORT_BY_NAME and calls CheckMatch.
 * ------------------------------------------------------------------------- */
void WalkThunks(
    BYTE*                base,
    IMAGE_NT_HEADERS64*  ntHeaders,
    IMAGE_THUNK_DATA64*  thunk,
    const char*          moduleName,
    const char*          filename,
    char**               targets,
    int                  targetCount,
    int                  prefixMode)
{
    while (thunk->u1.AddressOfData != 0)
    {
        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            thunk++;
            continue;
        }

        DWORD ibnOff = RvaToFileOffset(
            base, ntHeaders,
            (DWORD)thunk->u1.AddressOfData);

        if (ibnOff == 0) { thunk++; continue; }

        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + ibnOff);
        const char* funcName = (const char*)ibn->Name;

        CheckMatch(filename, moduleName, funcName,
                   targets, targetCount, prefixMode);

        thunk++;
    }
}


/* -------------------------------------------------------------------------
 * ScanImports
 * Locates the import directory, walks all IMAGE_IMPORT_DESCRIPTORs,
 * and calls WalkThunks for each imported module.
 * ------------------------------------------------------------------------- */
void ScanImports(
    BYTE*                base,
    IMAGE_NT_HEADERS64*  ntHeaders,
    const char*          filename,
    char**               targets,
    int                  targetCount,
    int                  prefixMode)
{
    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes
            <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return;

    IMAGE_DATA_DIRECTORY* importDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir->VirtualAddress == 0 || importDir->Size == 0) return;

    DWORD importOffset =
        RvaToFileOffset(base, ntHeaders, importDir->VirtualAddress);
    if (importOffset == 0) return;

    IMAGE_IMPORT_DESCRIPTOR* descriptor =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + importOffset);

    while (descriptor->Name != 0)
    {
        DWORD nameOff = RvaToFileOffset(base, ntHeaders, descriptor->Name);
        if (nameOff == 0) { descriptor++; continue; }

        const char* moduleName = (const char*)(base + nameOff);

        if (descriptor->OriginalFirstThunk != 0) {
            DWORD thunkOff = RvaToFileOffset(
                base, ntHeaders, descriptor->OriginalFirstThunk);

            if (thunkOff != 0) {
                IMAGE_THUNK_DATA64* thunk =
                    (IMAGE_THUNK_DATA64*)(base + thunkOff);

                WalkThunks(base, ntHeaders, thunk, moduleName,
                           filename, targets, targetCount, prefixMode);
            }
        }

        descriptor++;
    }
}


/* -------------------------------------------------------------------------
 * ScanFile
 * Loads a single file, validates it as a 64-bit PE, and scans its imports.
 * Non-PE files and 32-bit PEs are silently skipped.
 * ------------------------------------------------------------------------- */
void ScanFile(
    const char* path,
    char**       targets,
    int          targetCount,
    int          prefixMode)
{
    if (g_verbose)
        fprintf(stderr, "[scan] %s\n", path);

    DWORD fileSize = 0;
    BYTE* base = LoadFileToBuffer(path, &fileSize);
    if (!base) {
        if (g_verbose) fprintf(stderr, "[skip] cannot read: %s\n", path);
        return;
    }

    IMAGE_NT_HEADERS64* nt = GetNtHeaders64(base, fileSize);
    if (!nt) {
        if (g_verbose) fprintf(stderr, "[skip] not a 64-bit PE: %s\n", path);
        free(base);
        return;
    }

    const char* filename = strrchr(path, '\\');
    filename = filename ? filename + 1 : path;

    ScanImports(base, nt, filename, targets, targetCount, prefixMode);

    free(base);
}


/* -------------------------------------------------------------------------
 * ScanDirectory
 * Finds all *.sys files in a directory and calls ScanFile on each.
 * If recurse is non-zero, descends into subdirectories depth-first.
 * ------------------------------------------------------------------------- */
void ScanDirectory(
    const char* dir,
    char**       targets,
    int          targetCount,
    int          prefixMode,
    int          recurse)
{
    char pattern[MAX_PATH];

    if (g_verbose)
        fprintf(stderr, "[dir]  %s\n", dir);

    /* --- Scan .sys files in this directory --- */
    snprintf(pattern, sizeof(pattern), "%s\\*.sys", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            char fullPath[MAX_PATH];
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", dir, fd.cFileName);

            ScanFile(fullPath, targets, targetCount, prefixMode);

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    } else {
        if (g_verbose)
            fprintf(stderr, "[info] no .sys files in: %s\n", dir);
    }

    /* --- Recurse into subdirectories if requested --- */
    if (!recurse) return;

    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    hFind = FindFirstFileA(pattern, &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        if (g_verbose)
            fprintf(stderr, "[warn] cannot enumerate: %s (err %lu)\n",
                    dir, GetLastError());
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".")  == 0) continue;
        if (strcmp(fd.cFileName, "..") == 0) continue;

        char subDir[MAX_PATH];
        snprintf(subDir, sizeof(subDir), "%s\\%s", dir, fd.cFileName);

        ScanDirectory(subDir, targets, targetCount, prefixMode, recurse);

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}


/* -------------------------------------------------------------------------
 * LoadTargetList
 * Reads function names from a text file, one per line.
 * Lines starting with '#' and blank lines are ignored.
 * Returns the count of names loaded.
 * ------------------------------------------------------------------------- */
int LoadTargetList(const char* listFile, char** targets, int maxTargets)
{
    FILE* f = fopen(listFile, "r");
    if (!f) {
        fprintf(stderr, "Cannot open list file: %s\n", listFile);
        return 0;
    }

    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), f) && count < maxTargets) {
        char* nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char* cr = strchr(line, '\r'); if (cr) *cr = '\0';

        if (line[0] == '\0' || line[0] == '#') continue;

        targets[count++] = _strdup(line);
    }

    fclose(f);
    return count;
}


/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(int argc, char** argv)
{
    char  filePath[MAX_PATH] = {0};
    char  dirPath[MAX_PATH]  = {0};
    const char* listFile  = NULL;
    char*        targets[256] = {0};
    int          targetCount  = 0;
    int          dumpAll      = 0;
    int          prefixMode   = 0;
    int          recurse      = 0;

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(filePath, argv[++i], MAX_PATH - 1);
            StripTrailingSlash(filePath);
        }

        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(dirPath, argv[++i], MAX_PATH - 1);
            StripTrailingSlash(dirPath);
        }

        else if (strcmp(argv[i], "-t") == 0) {
            while (i + 1 < argc && argv[i + 1][0] != '-')
                targets[targetCount++] = argv[++i];
        }

        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc)
            listFile = argv[++i];

        else if (strcmp(argv[i], "--all") == 0)
            dumpAll = 1;

        else if (strcmp(argv[i], "--prefix") == 0)
            prefixMode = 1;

        else if (strcmp(argv[i], "-r") == 0 ||
                 strcmp(argv[i], "--recurse") == 0)
            recurse = 1;

        else if (strcmp(argv[i], "-v") == 0 ||
                 strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
    }

    if (listFile)
        targetCount += LoadTargetList(listFile,
                           targets + targetCount,
                           256 - targetCount);

    if (dumpAll) targetCount = 0;

    if (filePath[0] == '\0' && dirPath[0] == '\0') {
        fprintf(stderr,
            "Table Checker\n"
            "=================\n"
            "Usage:\n"
            "  TableChecker.exe -f <file>              scan a single file\n"
            "  TableChecker.exe -d <dir>               scan all .sys in a directory\n"
            "  TableChecker.exe -r, --recurse          also scan subdirectories\n"
            "  TableChecker.exe -t <name> [name...]    exact function name match\n"
            "  TableChecker.exe -l <listfile>          load targets from text file\n"
            "  TableChecker.exe --all                  dump every import\n"
            "  TableChecker.exe --prefix               treat -t values as prefixes\n"
            "  TableChecker.exe -v, --verbose          show directories being scanned\n"
            "\nExamples:\n"
            "  TableChecker.exe -f eneio64.sys -t ZwTerminateProcess MmMapIoSpace\n"
            "  TableChecker.exe -d C:\\Windows\\System32\\drivers -r --prefix -t Zw Mm Ps Ob\n"
            "  TableChecker.exe -d C:\\tools\\drivers -r -l targets.txt\n"
            "  TableChecker.exe -f mystery.sys --all\n"
            "  TableChecker.exe -d C:\\drivers -r -v --all\n"
            "\nOutput is tab-separated: redirect to .tsv for Excel/PowerShell.\n"
            "\nTip: use -v to see exactly which directories are being searched.\n");
        return 1;
    }

    printf("file\tmodule\tfunction\n");

    if (filePath[0] != '\0')
        ScanFile(filePath, targets, targetCount, prefixMode);
    else if (dirPath[0] != '\0')
        ScanDirectory(dirPath, targets, targetCount, prefixMode, recurse);

    return 0;
}
