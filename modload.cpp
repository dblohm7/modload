#include <windows.h>
#include <dbghelp.h>
#include <objbase.h>
#include <pathcch.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <string.h>
#include <time.h>

#include <comdef.h>
#include <comip.h>
#include <process.h>

#pragma comment(lib, "dbghelp")
#pragma comment(lib, "pathcch")
#pragma comment(lib, "shell32")
#pragma comment(lib, "shlwapi")

#if !defined(_M_X64)
#error 64-bit build only
#endif // !defined(_M_X64)

#define TRY_DEFAULT_BROWSER

struct LocalFreeDeleter
{
  void operator()(void* aPtr)
  {
    ::LocalFree(aPtr);
  }
};

struct ComDeleter
{
  void operator()(void* aPtr)
  {
    ::CoTaskMemFree(aPtr);
  }
};

struct KernelHandleDeleter
{
  void operator()(HANDLE aHandle)
  {
    if (aHandle == INVALID_HANDLE_VALUE) {
      return;
    }

    ::CloseHandle(aHandle);
  }
};

struct UpdateResourceDeleter
{
  void operator()(HANDLE aHandle)
  {
    ::EndUpdateResource(aHandle, FALSE);
  }
};

template <typename T, size_t N>
size_t ArrayLength(T (&aArray)[N])
{
  return N;
}

typedef std::unique_ptr<wchar_t, LocalFreeDeleter> UniquePathPtr;
typedef std::unique_ptr<LPWSTR, LocalFreeDeleter> UniqueArgvPtr;
typedef std::unique_ptr<wchar_t, ComDeleter> UniqueComStringPtr;
typedef std::unique_ptr<void, KernelHandleDeleter> UniqueKernelHandle;
typedef std::unique_ptr<void, UpdateResourceDeleter> UniqueResHandle;

_COM_SMARTPTR_TYPEDEF(IApplicationAssociationRegistration,
                      IID_IApplicationAssociationRegistration);
_COM_SMARTPTR_TYPEDEF(IFileOpenDialog, IID_IFileOpenDialog);
_COM_SMARTPTR_TYPEDEF(IFileSaveDialog, IID_IFileSaveDialog);
_COM_SMARTPTR_TYPEDEF(IShellItem, IID_IShellItem);

struct DebuggerContext
{
  enum class Op
  {
    CaptureDump,
    GenerateBin
  };

  DebuggerContext()
    : mOp(Op::CaptureDump)
  {
  }

  Op            mOp;
  std::wstring  mFirefoxPath;
  std::wstring  mCommandLineOptions;
  std::wstring  mModuleName;
  std::wstring  mDumpPath;
};

struct CrossPlatformContext
{
  CrossPlatformContext()
    : mIsWow64(false)
    , mPc(0LL)
    , mSp(0LL)
    , mFp(0LL)
  {}
  bool      mIsWow64;
  uint64_t  mPc;
  uint64_t  mSp;
  uint64_t  mFp;
};

class DeleteOnFail final
{
public:
  explicit DeleteOnFail(const wchar_t* aName)
    : mFileName(aName)
    , mSucceeded(false)
  {
  }

  ~DeleteOnFail()
  {
    if (mSucceeded) {
      return;
    }

    ::DeleteFile(mFileName.c_str());
  }

  void Succeeded()
  {
    mSucceeded = true;
  }

  DeleteOnFail(const DeleteOnFail&) = delete;
  DeleteOnFail(DeleteOnFail&&) = delete;
  DeleteOnFail& operator=(const DeleteOnFail&) = delete;
  DeleteOnFail& operator=(DeleteOnFail&&) = delete;

private:
  std::wstring  mFileName;
  bool          mSucceeded;
};

enum class ResId : WORD
{
  TargetModuleName = 0
};

static std::vector<wchar_t>
BuildStringTable(const std::array<std::wstring, 16>& aStrings)
{
  std::vector<wchar_t> result;

  for (auto&& str : aStrings) {
    result.push_back(str.length());
    std::copy(str.begin(), str.end(), std::back_inserter(result));
  }

  return result;
}

static bool
GenerateBinaryWithResources(const DebuggerContext& aDbgCtx)
{
  if (aDbgCtx.mModuleName.empty()) {
    return false;
  }

  wchar_t curExeName[MAX_PATH + 1] = {};
  DWORD result = ::GetModuleFileName(nullptr, curExeName, ArrayLength(curExeName));
  if (!result || result == ArrayLength(curExeName)) {
    return false;
  }

  wchar_t newExeName[MAX_PATH + 1] = {};
  if (wcscpy_s(newExeName, ArrayLength(newExeName), curExeName)) {
    return false;
  }

  HRESULT hr = ::PathCchRemoveExtension(newExeName, ArrayLength(newExeName));
  if (FAILED(hr)) {
    return false;
  }

  std::wstring suffix;
  suffix += L'-';
  suffix += aDbgCtx.mModuleName;
  suffix += L".exe";

  if (wcscat_s(newExeName, ArrayLength(newExeName), suffix.c_str())) {
    return false;
  }

  if (!::CopyFile(curExeName, newExeName, TRUE)) {
    return false;
  }

  { // So that we've committed the resources by the time we show UI
    DeleteOnFail del(newExeName);
    UniqueResHandle res(::BeginUpdateResource(newExeName, FALSE));
    if (!res) {
      return false;
    }

    std::array<std::wstring, 16> strings;
    strings[static_cast<WORD>(ResId::TargetModuleName)] = aDbgCtx.mModuleName;

    std::vector<wchar_t> stringTable(BuildStringTable(strings));
    if (!::UpdateResource(res.get(), RT_STRING, MAKEINTRESOURCE(1),
                          MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                          &stringTable[0], stringTable.size() * sizeof(wchar_t))) {
      return false;
    }

    del.Succeeded();
  }

  std::wostringstream oss;
  oss << L"Successfully created \"" << newExeName << L"\"";

  ::MessageBox(nullptr, oss.str().c_str(), L"Binary Generation Complete",
               MB_OK | MB_ICONASTERISK);

  return true;
}

static bool
GetCurrentContext(const PROCESS_INFORMATION& aProcInfo,
                  CrossPlatformContext& aOutContext)
{
  BOOL isWow64;
  if (!::IsWow64Process(aProcInfo.hProcess, &isWow64)) {
    return false;
  }

  aOutContext.mIsWow64 = !!isWow64;

  if (isWow64) {
    WOW64_CONTEXT ctx32{};
    ctx32.ContextFlags = WOW64_CONTEXT_CONTROL;
    if (!::Wow64GetThreadContext(aProcInfo.hThread, &ctx32)) {
      return false;
    }

    aOutContext.mPc = ctx32.Eip;
    aOutContext.mSp = ctx32.Esp;
    aOutContext.mFp = ctx32.Ebp;
  } else {
    CONTEXT ctx64{};
    ctx64.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!::GetThreadContext(aProcInfo.hThread, &ctx64)) {
      return false;
    }

    aOutContext.mPc = ctx64.Rip;
    aOutContext.mSp = ctx64.Rsp;
    aOutContext.mFp = ctx64.Rbp;
  }

  return true;
}

static void
OnDllLoad(const DEBUG_EVENT& aDbgEvt, const DebuggerContext& aDbgCtx,
          const PROCESS_INFORMATION& aProcInfo)
{
  HANDLE file = aDbgEvt.u.LoadDll.hFile;
  DWORD numCharsReqd = ::GetFinalPathNameByHandle(file, nullptr, 0, 0);
  if (!numCharsReqd) {
    return;
  }

  ++numCharsReqd;

  auto buf = std::make_unique<wchar_t[]>(numCharsReqd);
  DWORD numCharsWritten = ::GetFinalPathNameByHandle(file, buf.get(),
                                                     numCharsReqd, 0);
  if (!numCharsWritten || numCharsWritten >= numCharsReqd) {
    return;
  }

  std::wostringstream oss;
  oss << L"Loaded \"" << buf.get() << L"\"\n";
  ::OutputDebugStringW(oss.str().c_str());

  std::wstring module;
  std::transform(buf.get(), buf.get() + numCharsWritten,
                 std::back_inserter(module), ::tolower);

  std::wstring::size_type pos;
  pos = module.find(aDbgCtx.mModuleName, module.find_last_of(L'\\'));
  if (pos == std::wstring::npos) {
    return;
  }

  time_t now = time(nullptr);
  struct tm crackedNow;
  if (gmtime_s(&crackedNow, &now)) {
    return;
  }

  std::wostringstream suffix;
  suffix << std::setfill(L'0')
         << std::setw(2) << (crackedNow.tm_mon + 1)
         << std::setw(2) << crackedNow.tm_mday
         << std::setw(4) << (crackedNow.tm_year + 1900)
         << std::setw(2) << crackedNow.tm_hour
         << std::setw(2) << crackedNow.tm_min
         << std::setw(2) << crackedNow.tm_sec;

  std::wstring fullDumpPath(aDbgCtx.mDumpPath);
  if (fullDumpPath[fullDumpPath.length() - 1] != L'\\') {
    fullDumpPath += L'\\';
  }

  fullDumpPath += L"Mozilla-modload-";
  fullDumpPath += aDbgCtx.mModuleName;
  fullDumpPath += L'-';
  fullDumpPath += suffix.str();
  fullDumpPath += L".dmp";

  std::wostringstream dumpPathMsg;
  dumpPathMsg << L"Writing dump to \"" << fullDumpPath << L"\"\n";
  ::OutputDebugStringW(dumpPathMsg.str().c_str());

  UniqueKernelHandle dumpFile(
    ::CreateFile(fullDumpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                 FILE_ATTRIBUTE_NORMAL, nullptr));
  if (dumpFile.get() == INVALID_HANDLE_VALUE) {
    return;
  }

  MINIDUMP_TYPE minidumpType = (MINIDUMP_TYPE) (
                               MiniDumpNormal |
                               MiniDumpWithUnloadedModules |
                               MiniDumpWithModuleHeaders);
  // Let's just take a minidump of the process in this state
  BOOL ok = ::MiniDumpWriteDump(aProcInfo.hProcess, aProcInfo.dwProcessId,
                                dumpFile.get(), minidumpType, nullptr,
                                nullptr, nullptr);
  if (!ok) {
    return;
  }

  // TODO ASK: Write final name and success code to debug context so we can
  //           display a TaskDialog to the user at the end.
}

static unsigned __stdcall
DebuggerThread(void* aContext)
{
  DebuggerContext* context = reinterpret_cast<DebuggerContext*>(aContext);

  std::wstring fullCmdLine;
  fullCmdLine += L'\"';
  fullCmdLine += context->mFirefoxPath;
  fullCmdLine += L"\" ";
  fullCmdLine += context->mCommandLineOptions;

  STARTUPINFO si = { sizeof(si) };
  PROCESS_INFORMATION pi{};
  BOOL ok = ::CreateProcess(context->mFirefoxPath.c_str(),
                            const_cast<LPWSTR>(fullCmdLine.c_str()),
                            nullptr, nullptr, FALSE,
                            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS |
                              CREATE_UNICODE_ENVIRONMENT,
                            nullptr, nullptr, &si, &pi);
  if (!ok) {
    return 1;
  }

  UniqueKernelHandle childProcess(pi.hProcess);
  UniqueKernelHandle childInitialThread(pi.hThread);

  DEBUG_EVENT dbgEvt;

  bool continueDebugging = true;
  while (continueDebugging) {
    ok = ::WaitForDebugEvent(&dbgEvt, INFINITE);
    if (!ok) {
      ::TerminateProcess(pi.hProcess, 2);
      return 3;
    }

    DWORD continueStatus = DBG_CONTINUE;

    switch (dbgEvt.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT: {
        ::CloseHandle(dbgEvt.u.CreateProcessInfo.hFile);
        break;
      }
      case LOAD_DLL_DEBUG_EVENT: {
        OnDllLoad(dbgEvt, *context, pi);
        ::CloseHandle(dbgEvt.u.LoadDll.hFile);
        break;
      }
      case EXIT_PROCESS_DEBUG_EVENT: {
        continueDebugging = dbgEvt.dwProcessId != pi.dwProcessId;
        break;
      }
      case EXCEPTION_DEBUG_EVENT: {
        // Send breakpoints and all second-chance exceptions to crash reporter
        const EXCEPTION_DEBUG_INFO& exception = dbgEvt.u.Exception;
        if (exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
            !exception.dwFirstChance) {
          continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }
        break;
      }
      default:
        break;
    }

    ok = ::ContinueDebugEvent(dbgEvt.dwProcessId, dbgEvt.dwThreadId,
                              continueStatus);
    if (!ok) {
      ::TerminateProcess(pi.hProcess, 2);
      return 4;
    }
  }

  return 0;
}

static bool
IsPathFirefox(const std::wstring& aPath)
{
  std::wstring testPath;

  std::transform(aPath.begin(), aPath.end(), std::back_inserter(testPath),
                 ::tolower);

  std::wstring::size_type pos;
  pos = testPath.find(L"firefox.exe",
                      testPath.find_last_of(L'\\'));
  return pos != std::wstring::npos;
}

static bool
FindFirefox(std::wstring& aOutFirefoxPath)
{
  HRESULT hr;

#if defined(TRY_DEFAULT_BROWSER)

  // Try using the default http program
  IApplicationAssociationRegistrationPtr appRegInfo;
  hr = appRegInfo.CreateInstance(CLSID_ApplicationAssociationRegistration,
                                 nullptr, CLSCTX_INPROC_SERVER);
  if (FAILED(hr)) {
    return false;
  }

  LPWSTR rawProgId;
  hr = appRegInfo->QueryCurrentDefault(L"http", AT_URLPROTOCOL, AL_EFFECTIVE,
                                       &rawProgId);
  if (FAILED(hr)) {
    return false;
  }

  UniqueComStringPtr progId(rawProgId);

  DWORD reqdNumChars = 0;
  hr = ::AssocQueryString(ASSOCF_NOTRUNCATE | ASSOCF_INIT_IGNOREUNKNOWN,
                          ASSOCSTR_EXECUTABLE, rawProgId, L"open", nullptr,
                          &reqdNumChars);
  if (FAILED(hr) || hr != S_FALSE) {
    return false;
  }

  auto exeBuf = std::make_unique<wchar_t[]>(reqdNumChars);
  if (!exeBuf) {
    return false;
  }

  hr = ::AssocQueryString(ASSOCF_NOTRUNCATE | ASSOCF_INIT_IGNOREUNKNOWN,
                          ASSOCSTR_EXECUTABLE, rawProgId, L"open", exeBuf.get(),
                          &reqdNumChars);
  if (FAILED(hr)) {
    return false;
  }

  if (IsPathFirefox(exeBuf.get())) {
    aOutFirefoxPath = exeBuf.get();
    return true;
  }

#endif // defined(TRY_DEFAULT_BROWSER)

  // Uh-oh. We can't find Firefox! Show a picker?
  IFileOpenDialogPtr picker;
  hr = picker.CreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER);
  if (FAILED(hr)) {
    return true;
  }

  IShellItemPtr programDir;
  hr = ::SHGetKnownFolderItem(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT,
                              nullptr, IID_IShellItem, (void**) &programDir);
  if (FAILED(hr)) {
    return false;
  }

  hr = picker->SetFolder(programDir);
  if (FAILED(hr)) {
    return false;
  }

  COMDLG_FILTERSPEC fltSpec = {L"Executable Files", L"*.exe"};
  hr = picker->SetFileTypes(1, &fltSpec);
  if (FAILED(hr)) {
    return hr;
  }

  hr = picker->SetFileTypeIndex(1); // one-based
  if (FAILED(hr)) {
    return hr;
  }

  hr = picker->SetFileName(L"firefox.exe");
  if (FAILED(hr)) {
    return hr;
  }

  FILEOPENDIALOGOPTIONS options;
  hr = picker->GetOptions(&options);
  if (FAILED(hr)) {
    return false;
  }

  options |= FOS_STRICTFILETYPES | FOS_FORCEFILESYSTEM |
             FOS_FILEMUSTEXIST | FOS_DONTADDTORECENT;

  hr = picker->SetOptions(options);
  if (FAILED(hr)) {
    return false;
  }

  hr = picker->SetTitle(L"Location of Firefox Executable");
  if (FAILED(hr)) {
    return false;
  }

  // Modal
  hr = picker->Show(nullptr);
  if (FAILED(hr)) {
    return false;
  }

  IShellItemPtr selection;
  hr = picker->GetResult(&selection);
  if (FAILED(hr)) {
    return false;
  }

  LPWSTR rawFileName;
  hr = selection->GetDisplayName(SIGDN_FILESYSPATH, &rawFileName);
  if (FAILED(hr)) {
    return false;
  }

  UniqueComStringPtr fileName(rawFileName);
  if (!IsPathFirefox(rawFileName)) {
    return false;
  }

  aOutFirefoxPath = rawFileName;
  return true;
}

static bool
GetDumpPath(std::wstring& aOutDumpPath)
{
  aOutDumpPath.clear();

  IFileOpenDialogPtr picker;
  HRESULT hr = picker.CreateInstance(CLSID_FileOpenDialog, nullptr,
                                     CLSCTX_INPROC_SERVER);
  if (FAILED(hr)) {
    return false;
  }

  IShellItemPtr docsDir;
  hr = ::SHGetKnownFolderItem(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr,
                              IID_IShellItem, (void**) &docsDir);
  if (FAILED(hr)) {
    return false;
  }

  hr = picker->SetFolder(docsDir);
  if (FAILED(hr)) {
    return false;
  }

  FILEOPENDIALOGOPTIONS options;
  hr = picker->GetOptions(&options);
  if (FAILED(hr)) {
    return false;
  }

  options |= FOS_PICKFOLDERS;
  hr = picker->SetOptions(options);
  if (FAILED(hr)) {
    return false;
  }

  hr = picker->SetTitle(L"Destination for Minidump File");
  if (FAILED(hr)) {
    return false;
  }

  // Modal
  hr = picker->Show(nullptr);
  if (FAILED(hr)) {
    return false;
  }

  IShellItemPtr selection;
  hr = picker->GetResult(&selection);
  if (FAILED(hr)) {
    return false;
  }

  LPWSTR rawFileName;
  hr = selection->GetDisplayName(SIGDN_FILESYSPATH, &rawFileName);
  if (FAILED(hr)) {
    return false;
  }

  UniqueComStringPtr fileName(rawFileName);
  aOutDumpPath = rawFileName;
  return true;
}

static bool
GetTargetModule(std::wstring& aOutTargetModule)
{
  aOutTargetModule.clear();

  wchar_t buf[MAX_PATH + 1] = {};
  if (!::LoadString(::GetModuleHandle(nullptr),
                    static_cast<WORD>(ResId::TargetModuleName),
                    buf, ArrayLength(buf))) {
    return false;
  }

  aOutTargetModule = buf;

  return true;
}

static const wchar_t* kCmdLineSwitches[] {
  L"--modload-target-module",
  L"--modload-target-firefox",
  L"--modload-dump-path"
};

static bool
GetLocations(int aArgc, LPWSTR* aArgv, DebuggerContext& aDbgCtx)
{
  aDbgCtx.mFirefoxPath.clear();
  aDbgCtx.mModuleName.clear();

  for (int i = 0; i < aArgc; ++i) {
    if (!wcscmp(aArgv[i], kCmdLineSwitches[0]) && (i + 1) < aArgc) {
      wcslwr(aArgv[i + 1]);
      aDbgCtx.mModuleName = aArgv[i + 1];
      ++i;
      continue;
    }

    if (!wcscmp(aArgv[i], kCmdLineSwitches[1]) && (i + 1) < aArgc) {
      PWSTR rawCanonical;
      HRESULT hr = ::PathAllocCanonicalize(aArgv[i + 1], PATHCCH_NONE,
                                           &rawCanonical);
      if (FAILED(hr)) {
        return false;
      }

      UniquePathPtr canonical(rawCanonical);
      aDbgCtx.mFirefoxPath = rawCanonical;
      ++i;
      continue;
    }

    if (!wcscmp(aArgv[i], kCmdLineSwitches[2]) && (i + 1) < aArgc) {
      PWSTR rawCanonical;
      HRESULT hr = ::PathAllocCanonicalize(aArgv[i + 1], PATHCCH_NONE,
                                           &rawCanonical);
      if (FAILED(hr)) {
        return false;
      }

      UniquePathPtr canonical(rawCanonical);
      aDbgCtx.mDumpPath = rawCanonical;
      ++i;
      continue;
    }

    if (!wcscmp(aArgv[i], L"--modload-generate-binary")) {
      aDbgCtx.mOp = DebuggerContext::Op::GenerateBin;
    }
  }

  if (aDbgCtx.mOp == DebuggerContext::Op::GenerateBin) {
    return true;
  }

  bool success = true;

  if (aDbgCtx.mFirefoxPath.empty()) {
    success &= FindFirefox(aDbgCtx.mFirefoxPath);
  }

  if (aDbgCtx.mModuleName.empty()) {
    success &= GetTargetModule(aDbgCtx.mModuleName);
  }

  if (aDbgCtx.mDumpPath.empty()) {
    success &= GetDumpPath(aDbgCtx.mDumpPath);
  }

  return success;
}

static void
BuildDebugeeCommandLineOptions(int argc, LPWSTR* aArgv, std::wstring& aOutCmdLine)
{
  aOutCmdLine.clear();

  for (int i = 0; i < argc; ++i) {
    bool foundOwnOption = false;
    for (int j = 0; j < ArrayLength(kCmdLineSwitches); ++j) {
      if (!wcscmp(aArgv[i], kCmdLineSwitches[j])) {
        ++i;
        foundOwnOption = true;
        break;
      }
    }

    if (foundOwnOption) {
      continue;
    }

    if (!aOutCmdLine.empty()) {
      aOutCmdLine += L' ';
    }

    aOutCmdLine += aArgv[i];
  }
}

template <COINIT Type>
class COMRegion final
{
public:
  COMRegion()
    : mResult(::CoInitializeEx(nullptr, Type | COINIT_DISABLE_OLE1DDE))
  {
  }

  ~COMRegion()
  {
    if (FAILED(mResult)) {
      return;
    }

    ::CoUninitialize();
  }

  COMRegion(const COMRegion&) = delete;
  COMRegion(COMRegion&&) = delete;
  COMRegion& operator=(const COMRegion&) = delete;
  COMRegion& operator=(COMRegion&&) = delete;

private:
  HRESULT mResult;
};

typedef COMRegion<COINIT_APARTMENTTHREADED> STARegion;
typedef COMRegion<COINIT_MULTITHREADED> MTARegion;

int WINAPI
wWinMain(HINSTANCE aInstance, HINSTANCE aPrevInstance, PWSTR aCmdLine,
         int aCmdShow)
{
  int argc;
  UniqueArgvPtr argv(::CommandLineToArgvW(aCmdLine, &argc));
  if (!argv) {
    return 1;
  }

  STARegion sta;

  DebuggerContext dbgctx;
  if (!GetLocations(argc, argv.get(), dbgctx)) {
    return 2;
  }

  std::wstring output(L"Firefox Binary: \"");
  output += dbgctx.mFirefoxPath;
  output += L"\"\n";
  ::OutputDebugStringW(output.c_str());

  output = L"Desired module: \"";
  output += dbgctx.mModuleName;
  output += L"\"\n";
  ::OutputDebugStringW(output.c_str());

  if (dbgctx.mOp == DebuggerContext::Op::GenerateBin) {
    if (!GenerateBinaryWithResources(dbgctx)) {
      return 3;
    }
    return 0;
  }

  BuildDebugeeCommandLineOptions(argc, argv.get(), dbgctx.mCommandLineOptions);

  unsigned tid;
  UniqueKernelHandle handle(reinterpret_cast<HANDLE>(
    _beginthreadex(nullptr, 0, &DebuggerThread, &dbgctx, 0, &tid)));
  if (!handle) {
    return 4;
  }

  HANDLE waitHandle = handle.get();
  DWORD waitIndex;
  HRESULT hr = ::CoWaitForMultipleHandles(0, INFINITE, 1, &waitHandle, &waitIndex);
  if (FAILED(hr)) {
    return 5;
  }

  return 0;
}

