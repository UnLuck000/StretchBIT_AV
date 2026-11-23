// Пункт «Проверить в StretchBIT» в новом контекстном меню Windows 11.
//
// Windows 11 больше не показывает в своём новом меню записи HKCR\*\shell (они уходят в
// «Показать больше параметров»). Чтобы попасть в верхний уровень, нужен COM-сервер
// IExplorerCommand, зарегистрированный через sparse-пакет (AppxManifest.xml рядом).
//
// Сборка: python native/menu/build.py (нужна Visual Studio C++ и Windows SDK).
// Командой Invoke запускает StretchBIT.exe --analyze "<выбранный файл>" — то же, что и
// прежний пункт меню Проводника (ui/settings.py set_explorer_menu).
#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <new>

// CLSID пункта меню (генерируется один раз; тот же — в AppxManifest.xml).
static const GUID CLSID_MenuCommand = {
    0x7f3d2c1a, 0x9b4e, 0x4d6f, {0xa8, 0x31, 0xc2, 0x5d, 0x7e, 0x0f, 0x1a, 0x9b}};

namespace {

// Получить путь выбранного файла из IShellItemArray (первый элемент).
HRESULT FirstItemPath(IShellItemArray* items, PWSTR* out) {
    *out = nullptr;
    DWORD count = 0;
    if (items == nullptr) return E_INVALIDARG;
    HRESULT hr = items->GetCount(&count);
    if (FAILED(hr) || count == 0) return E_INVALIDARG;
    IShellItem* item = nullptr;
    hr = items->GetItemAt(0, &item);
    if (FAILED(hr)) return hr;
    PWSTR path = nullptr;
    hr = item->GetDisplayName(SIGDN_FILESYSPATH, &path);
    item->Release();
    if (SUCCEEDED(hr) && path) {
        *out = path;
        return S_OK;
    }
    CoTaskMemFree(path);
    return hr;
}

// Запустить StretchBIT.exe --analyze "<путь>".
HRESULT LaunchAnalyze(PCWSTR path) {
    // путь программы: рядом с этой DLL (в папке программы) или в Program Files
    wchar_t exe[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
    if (n == 0 || n >= ARRAYSIZE(exe)) return E_FAIL;
    // DLL лежит в папке программы: StretchBIT.exe — там же (имя DLL — sbit_menu.dll)
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (slash == nullptr) return E_FAIL;
    *(slash + 1) = L'\0';
    if (FAILED(StringCchCatW(exe, ARRAYSIZE(exe), L"StretchBIT.exe"))) return E_FAIL;

    wchar_t cmdline[MAX_PATH * 4];
    if (FAILED(StringCchPrintfW(cmdline, ARRAYSIZE(cmdline),
                                L"\"%s\" --analyze \"%s\"", exe, path))) return E_FAIL;

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                             &si, &pi);
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return S_OK;
}

// IExplorerCommand + IObjectWithSite: нужен только IExplorerCommand, IObjectWithSite — для
// совместимости (проводник может запросить его до вызова).
class MenuCommand final : public IExplorerCommand {
public:
    MenuCommand() : m_ref(1) {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        static const QITAB qit[] = {
            QITABENT(MenuCommand, IExplorerCommand),
            {nullptr, 0},
        };
        return QISearch(this, qit, riid, ppv);
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&m_ref); }
    IFACEMETHODIMP_(ULONG) Release() {
        ULONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* name) {
        return SHStrDupW(L"Проверить в StretchBIT", name);
    }
    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* icon) {
        // значок программы (рядом с DLL); без него проводник покажет значок по умолчанию
        wchar_t exe[MAX_PATH * 2];
        DWORD n = GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
        if (n == 0 || n >= ARRAYSIZE(exe)) return E_FAIL;
        wchar_t* slash = wcsrchr(exe, L'\\');
        if (slash == nullptr) return E_FAIL;
        *(slash + 1) = L'\0';
        StringCchCatW(exe, ARRAYSIZE(exe), L"StretchBIT.exe,0");
        return SHStrDupW(exe, icon);
    }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* tip) {
        return SHStrDupW(L"Проверить файл антивирусом StretchBIT", tip);
    }
    IFACEMETHODIMP GetCanonicalName(GUID* guid) {
        *guid = CLSID_MenuCommand;
        return S_OK;
    }
    IFACEMETHODIMP GetState(IShellItemArray*, BOOL ok, EXPCMDSTATE* state) {
        *state = ok ? ECS_ENABLED : ECS_HIDDEN;
        return S_OK;
    }
    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) {
        PWSTR path = nullptr;
        HRESULT hr = FirstItemPath(items, &path);
        if (FAILED(hr)) return hr;
        hr = LaunchAnalyze(path);
        CoTaskMemFree(path);
        return hr;
    }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* flags) {
        *flags = ECF_DEFAULT;
        return S_OK;
    }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** ppEnum) {
        *ppEnum = nullptr;
        return E_NOTIMPL;
    }

private:
    volatile ULONG m_ref;
};

}  // namespace

// ---------- COM-сервер (in-proc DLL) ----------
static volatile ULONG g_lock = 0;

class MenuClassFactory final : public IClassFactory {
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        static const QITAB qit[] = {
            QITABENT(MenuClassFactory, IClassFactory),
            {nullptr, 0},
        };
        return QISearch(this, qit, riid, ppv);
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return 2; }
    IFACEMETHODIMP_(ULONG) Release() { return 1; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) {
        if (outer) return CLASS_E_NOAGGREGATION;
        MenuCommand* obj = new (std::nothrow) MenuCommand();
        if (obj == nullptr) return E_OUTOFMEMORY;
        HRESULT hr = obj->QueryInterface(riid, ppv);
        obj->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) {
        if (lock) InterlockedIncrement(&g_lock);
        else InterlockedDecrement(&g_lock);
        return S_OK;
    }
};

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid != CLSID_MenuCommand) return CLASS_E_CLASSNOTAVAILABLE;
    MenuClassFactory* f = new (std::nothrow) MenuClassFactory();
    if (f == nullptr) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow() { return g_lock == 0 ? S_OK : S_FALSE; }

STDAPI_(BOOL) DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(nullptr);
    return TRUE;
}
