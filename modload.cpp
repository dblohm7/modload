#include <windows.h>
#include <objbase.h>
#include <pathcch.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>

#include <string.h>

#include <comdef.h>
#include <comip.h>

#pragma comment(lib, "pathcch")
#pragma comment(lib, "shell32")
#pragma comment(lib, "shlwapi")

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

typedef std::unique_ptr<wchar_t, LocalFreeDeleter> UniquePathPtr;
typedef std::unique_ptr<LPWSTR, LocalFreeDeleter> UniqueArgvPtr;
typedef std::unique_ptr<wchar_t, ComDeleter> UniqueComStringPtr;

_COM_SMARTPTR_TYPEDEF(IApplicationAssociationRegistration,
                      IID_IApplicationAssociationRegistration);
_COM_SMARTPTR_TYPEDEF(IFileOpenDialog, IID_IFileOpenDialog);
_COM_SMARTPTR_TYPEDEF(IShellItem, IID_IShellItem);
_COM_SMARTPTR_TYPEDEF(IShellItem2, IID_IShellItem2);

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

  IShellItem2Ptr programDir;
  hr = ::SHGetKnownFolderItem(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT,
                              nullptr, IID_IShellItem2, (void**) &programDir);
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

  hr = picker->SetOptions(FOS_STRICTFILETYPES | FOS_FORCEFILESYSTEM |
                          FOS_FILEMUSTEXIST | /*FOS_SHAREAWARE |*/
                          FOS_DONTADDTORECENT);
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
GetTargetModule(std::wstring& aOutTargetModule)
{
  return true;
}

static const wchar_t* kCmdLineSwitches[] {
  L"--modload-target-module",
  L"--modload-target-firefox"
};

static bool
GetBinaries(int aArgc, LPWSTR* aArgv, std::wstring& aOutFirefoxPath,
            std::wstring& aOutTargetModule)
{
  aOutFirefoxPath.clear();
  aOutTargetModule.clear();

  for (int i = 1; i < aArgc; ++i) {
    if (!wcscmp(aArgv[i], kCmdLineSwitches[0]) && (i + 1) < aArgc) {
      aOutTargetModule = aArgv[i + 1];
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
      aOutFirefoxPath = rawCanonical;
      ++i;
      continue;
    }
  }

  bool success = true;

  if (aOutFirefoxPath.empty()) {
    success &= FindFirefox(aOutFirefoxPath);
  }

  if (aOutTargetModule.empty()) {
    success &= GetTargetModule(aOutTargetModule);
  }

  return success;
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

  std::wstring targetModule;
  std::wstring firefoxBinary;
  if (!GetBinaries(argc, argv.get(), firefoxBinary, targetModule)) {
    return 2;
  }

  std::wstring output(firefoxBinary);
  output += L'\n';
  ::OutputDebugStringW(output.c_str());

  return 0;
}

