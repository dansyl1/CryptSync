// CryptSync - A folder sync tool with encryption

// Copyright (C) 2012-2014, 2016, 2019, 2021, 2024 - Stefan Kueng

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//

#include "stdafx.h"
#include "resource.h"
#include "OptionsDlg.h"
#include "Registry.h"
#include "PairAddDlg.h"
#include "UpdateDlg.h"
#include "AboutDlg.h"
#include "TextDlg.h"
#include "Ignores.h"
#include "StringUtils.h"
#include "CircularLog.h"
#include "ResString.h"
#include "OnOutOfScope.h"

#include <string>
#include <algorithm>
#include <Commdlg.h>
#include <cassert>

COptionsDlg::COptionsDlg(HWND hParent, CFolderSync& folderSync)
    : m_hParent(hParent)
    , m_folderSync(folderSync)
    , m_bNewerVersionAvailable(false)
    , m_exitAfterSync(false)
    , m_listInit(false)
{
}

COptionsDlg::~COptionsDlg()
{
}

LRESULT COptionsDlg::DlgFunc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            InitDialog(hwndDlg, IDI_CryptSync);

            m_link.ConvertStaticToHyperlink(hwndDlg, IDC_ABOUT, _T(""));

            AddToolTip(IDC_AUTOSTART, L"Starts CryptSync automatically when Windows starts up.");
            AddToolTip(IDC_IGNORELABEL, L"Ignore masks, separated by '|' example: *.tmp|~*.*");
            AddToolTip(IDC_IGNORE, L"Ignore masks, separated by '|' example: *.tmp|~*.*");

            // initialize the controls
            CRegStdString regStart(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CryptSync"));
            bool          bStartWithWindows = !std::wstring(regStart).empty();
            SendDlgItemMessage(*this, IDC_AUTOSTART, BM_SETCHECK, bStartWithWindows ? BST_CHECKED : BST_UNCHECKED, NULL);
            SendDlgItemMessage(*this, IDC_AUTOSTART, BM_SETCHECK, bStartWithWindows ? BST_CHECKED : BST_UNCHECKED, NULL);
            CRegStdString regIgnores(L"Software\\CryptSync\\Ignores", DEFAULT_IGNORES);
            std::wstring  sIgnores = regIgnores;
            SetDlgItemText(*this, IDC_IGNORE, sIgnores.c_str());

            CRegStdDWORD regInterval(L"Software\\CryptSync\\FullScanInterval", 60000 * 30);
            UINT         intVal = static_cast<DWORD>(regInterval);
            intVal /= 60000;
            std::wstring sInterval = CStringUtils::Format(L"%d", intVal);
            SetDlgItemText(*this, IDC_INTERVAL, sInterval.c_str());

            InitPairList();

            DialogEnableWindow(IDC_SHOWFAILURES, !m_failures.empty());

            if (m_bNewerVersionAvailable)
            {
                CUpdateDlg dlg(*this);
                dlg.DoModal(hResource, IDD_NEWERNOTIFYDLG, *this);
                m_bNewerVersionAvailable = false;
            }
        }
            return TRUE;
        case WM_COMMAND:
            return DoCommand(LOWORD(wParam));
        case WM_THREADENDED:
            if (m_exitAfterSync)
            {
                EndDialog(*this, IDEXIT);
                return TRUE;
            }
            return FALSE;
        case WM_NOTIFY:
        {
            if (wParam == IDC_SYNCPAIRS)
            {
                DoListNotify(reinterpret_cast<LPNMITEMACTIVATE>(lParam));
            }
        }
            return FALSE;
        case WM_CONTEXTMENU:
        {
            HWND  hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu    = LoadMenu(hResource, MAKEINTRESOURCE(IDR_PAIRMENU));
            HMENU hPopMenu = GetSubMenu(hMenu, 0);
            // Enable/disable menu (similar to what is done in DoListNotify() method)
            EnableMenuItem(hMenu, ID_DELETE, (ListView_GetSelectedCount(hListControl)) > 0 ? MF_ENABLED : MF_GRAYED);
            EnableMenuItem(hMenu, ID_EDIT, (ListView_GetSelectedCount(hListControl)) == 1 ? MF_ENABLED : MF_GRAYED);
            TrackPopupMenu(hPopMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, *this, nullptr);
            DestroyMenu(hMenu);
        }
            return FALSE;
        default:
            return FALSE;
    }
}

void COptionsDlg::DoPairEdit(int iItem)
{
    HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
    int  nCount       = ListView_GetItemCount(hListControl);
    if (nCount == 0)
        return;
    LVITEM lv         = {};
    lv.iItem          = iItem;
    lv.iSubItem       = 0;
    lv.mask           = LVIF_PARAM;
    ListView_GetItem(hListControl, &lv);

    if ((lv.lParam < 0) || (lv.lParam >= static_cast<int>(g_pairs.size())))
        return;

    auto& t = g_pairs[lv.lParam];

    CPairAddDlg dlg(*this);
    dlg.m_origPath              = t.m_origPath;
    dlg.m_cryptPath             = t.m_cryptPath;
    dlg.m_password              = t.m_password;
    dlg.m_cryptOnly             = t.cryptOnly();
    dlg.m_copyOnly              = t.copyOnly();
    dlg.m_noSync                = t.noSync();
    dlg.m_encNames              = t.m_encNames;
    dlg.m_encNamesNew           = t.m_encNamesNew;
    dlg.m_syncDir               = t.m_syncDir;
    dlg.m_7ZExt                 = t.m_use7Z;
    dlg.m_useGpg                = t.m_useGpg;
    dlg.m_fat                   = t.m_fat;
    dlg.m_compressSize          = t.m_compressSize;
    dlg.m_syncDeleted           = t.m_syncDeleted;
    dlg.m_ResetOriginalArchAttr = t.m_ResetOriginalArchAttr;
    if (dlg.DoModal(hResource, IDD_PAIRADD, *this) == IDOK)
    {
        if (!dlg.m_origPath.empty() && !dlg.m_cryptPath.empty())
        {
            bool bEnabled = ListView_GetCheckState(hListControl, iItem);
            auto pd       = PairData(bEnabled, dlg.m_origPath, dlg.m_cryptPath, dlg.m_password, dlg.m_cryptOnly, dlg.m_copyOnly, dlg.m_noSync, dlg.m_compressSize, dlg.m_encNames, dlg.m_encNamesNew, dlg.m_syncDir, dlg.m_7ZExt, dlg.m_useGpg, dlg.m_fat, dlg.m_syncDeleted, dlg.m_ResetOriginalArchAttr);

            // Check if new pd uses same paths as another pair
            auto foundIt = std::find(g_pairs.begin(), g_pairs.end(), pd);
            if (foundIt != g_pairs.end())
            {
                if (lv.lParam == distance(g_pairs.begin(), foundIt))
                {
                    // found pair user was editing
                    *foundIt = pd;
                }
                else
                {
                    // found another pair (ie, user changed paths)
                    if (foundIt->m_syncDir == ToBeDeleted)
                    { // Pair is empty, re-use it.
                        t.m_syncDir = ToBeDeleted;
                        *foundIt    = pd;
                    }
                    else
                    {
                        // User edited paths and new paths
                        // are same as another enabled pair. Ignore edits.
                        MessageBox(*this, L"A pair with same paths already exists. Edits ignored.", L"CryptSync", MB_OK | MB_ICONERROR);
                    }
                }
            }
            else
            {
                // pd is for new paths, PairData that got edited will be disabled and
                // new pair created.
                MessageBox(*this, L"A new pair will be created with specified paths, replacing the pair you edited.", L"CryptSync", MB_OK | MB_ICONWARNING);
                t.m_syncDir = ToBeDeleted;
                t.m_enabled = false;
                g_pairs.push_back(pd); // Edition resulted in new pd
            }
            InitPairList();
            g_pairs.SavePairs();
        }
    }
}

LRESULT COptionsDlg::DoCommand(int id)
{
    switch (id)
    {
        case IDOK:
        {
            SaveSettings();
        }
            [[fallthrough]];
        case IDCANCEL:
            [[fallthrough]];
        case IDEXIT:
            if ((id == IDEXIT) && MessageBox(*this, L"Are you sure you want to quit?", L"CryptSync", MB_ICONQUESTION | MB_YESNO) != IDYES)
                return 1;
            EndDialog(*this, id);
            break;
        case IDC_SHOWLOG:
        {
            CCircularLog::Instance().Save();
            std::wstring     path = CCircularLog::Instance().GetSavePath();
            SHELLEXECUTEINFO shex = {0};
            shex.cbSize           = sizeof(SHELLEXECUTEINFO);
            shex.fMask            = SEE_MASK_DOENVSUBST | SEE_MASK_ASYNCOK | SEE_MASK_CLASSNAME;
            shex.hwnd             = *this;
            shex.lpVerb           = nullptr;
            shex.lpFile           = path.c_str();
            shex.lpClass          = L".txt";
            shex.nShow            = SW_SHOWNORMAL;
            if (!ShellExecuteEx(&shex))
            {
                shex.fMask        = SEE_MASK_DOENVSUBST | SEE_MASK_ASYNCOK;
                shex.hwnd         = *this;
                shex.lpFile       = L"%windir%\\notepad.exe";
                shex.lpParameters = path.c_str();
                shex.nShow        = SW_SHOWNORMAL;
                ShellExecuteEx(&shex);
            }
        }
        break;
        case IDC_SYNCEXIT:
        case ID_FILE_SYNCNOW:
        {
            SaveSettings();
            m_exitAfterSync = id == IDC_SYNCEXIT;
            m_folderSync.SyncFolders(g_pairs, *this);
        }
        break;
        case IDC_CREATEPAIR:
        {
            CPairAddDlg dlg(*this);
            if (dlg.DoModal(hResource, IDD_PAIRADD, *this) == IDOK)
            {
                if (!dlg.m_origPath.empty() && !dlg.m_cryptPath.empty())
                {
                    auto pd       = PairData(true, dlg.m_origPath, dlg.m_cryptPath, dlg.m_password, dlg.m_cryptOnly, dlg.m_copyOnly, dlg.m_noSync, dlg.m_compressSize, dlg.m_encNames, dlg.m_encNamesNew, dlg.m_syncDir, dlg.m_7ZExt, dlg.m_useGpg, dlg.m_fat, dlg.m_syncDeleted, dlg.m_ResetOriginalArchAttr);
                    // Ignore new pd if it is on same paths as another pair
                    auto foundIt = std::find(g_pairs.begin(), g_pairs.end(), pd);
                    if (foundIt == g_pairs.end() || foundIt->m_syncDir == ToBeDeleted)
                    {
                        // Append new PairData to g_pairs
                        if (foundIt == g_pairs.end())
                            g_pairs.push_back(pd);
                        else // Re-use "ToBeDeleted" PairData, otherwise ignore new item
                            *foundIt = pd;
                        InitPairList();
                        g_pairs.SavePairs();
                    }
                    else
                    {
                        MessageBox(*this, L"A pair with same paths already exists. New pair not created.", L"CryptSync", MB_OK | MB_ICONERROR);
                    }
                }
            }
        }
        break;
        case ID_EDIT:
        case IDC_EDITPAIR:
        {
            HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
            int  nCount       = ListView_GetItemCount(hListControl);
            if (nCount == 0)
                break;
            LVITEM lv   = {};
            lv.iItem    = -1;
            lv.iSubItem = 0;
            lv.mask     = LVIF_PARAM;
            while ((lv.iItem = ListView_GetNextItem(hListControl, lv.iItem, LVNI_SELECTED)) != (-1))
            {
                if ((lv.iItem < 0) || (lv.iItem >= static_cast<int>(ListView_GetItemCount(hListControl))))
                    continue;
                DoPairEdit(lv.iItem);
                break;
            }
        }
        break;
        case ID_DELETE:
        case IDC_DELETEPAIR:
        {
            HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
            int  nCount       = ListView_GetItemCount(hListControl);
            if (nCount == 0)
                break;

            LVITEM lv        = {};
            lv.iItem         = -1;
            lv.iSubItem      = 0;
            lv.mask          = LVIF_PARAM;
            PairVector sels;
            while ((lv.iItem = ListView_GetNextItem(hListControl, lv.iItem, LVNI_SELECTED)) != (-1))
            {
                if ((lv.iItem < 0) || (lv.iItem >= static_cast<int>(ListView_GetItemCount(hListControl))))
                    continue;
                ListView_GetItem(hListControl, &lv);
                if ((lv.lParam < 0) || (lv.lParam >= static_cast<int>(g_pairs.size())))
                    continue;
                sels.push_back(g_pairs[lv.lParam]);
            }

            if (!sels.empty())
            {
                ResString rDelquestion(hResource, IDS_ASK_DELETEPAIR);
                auto      sQuestion = CStringUtils::Format(rDelquestion, static_cast<int>(sels.size()));
                if (MessageBox(*this, sQuestion.c_str(), L"CryptSync", MB_YESNO | MB_DEFBUTTON2) != IDYES)
                    break;
            }

            for (auto it = sels.cbegin(); it != sels.cend(); ++it)
            {
                auto foundIt = std::find(g_pairs.begin(), g_pairs.end(), *it);
                if (foundIt != g_pairs.end())
                {
                    foundIt->m_syncDir = ToBeDeleted;
                }
            }
            InitPairList();
            g_pairs.SavePairs();
        }
        break;
        case IDC_ABOUT:
        {
            CAboutDlg dlgAbout(*this);
            dlgAbout.DoModal(hResource, IDD_ABOUTBOX, *this);
        }
        break;
        case IDC_SHOWFAILURES:
        {
            std::wstring sFailures = L"the following paths failed to sync:\r\n";
            for (auto it = m_failures.cbegin(); it != m_failures.cend(); ++it)
            {
                if (it->second == Encrypt)
                    sFailures += L"Encrypting : ";
                else
                    sFailures += L"Decrypting : ";
                sFailures += it->first;
                sFailures += L"\r\n";
            }
            CTextDlg dlg(*this);
            dlg.m_text = sFailures;
            dlg.DoModal(hResource, IDD_TEXTDLG, *this);
        }
        break;
        case ID_SYNCNOW:
        case ID_SYNCNOWANDEXIT:
        {
            SaveSettings();
            HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
            int  nCount       = ListView_GetItemCount(hListControl);
            if (nCount == 0)
                break;
            LVITEM lv   = {};
            lv.iItem    = -1;
            lv.iSubItem = 0;
            lv.mask     = LVIF_PARAM;
            PairVector sels;
            while ((lv.iItem = ListView_GetNextItem(hListControl, lv.iItem, LVNI_SELECTED)) != (-1))
            {
                if ((lv.iItem < 0) || (lv.iItem >= static_cast<int>(ListView_GetItemCount(hListControl))))
                    continue;
                ListView_GetItem(hListControl, &lv);
                if ((lv.lParam < 0) || (lv.lParam >= static_cast<int>(g_pairs.size())))
                    continue;
                sels.push_back(g_pairs[lv.lParam]);
            }
            m_exitAfterSync = (id == ID_SYNCNOWANDEXIT);
            m_folderSync.SyncFolders(sels, *this);
        }
        break;
    }
    return 1;
}

void COptionsDlg::InitPairList()
{
    m_listInit = true;
    OnOutOfScope(m_listInit = false);

    HWND  hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
    DWORD exStyle      = LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES;
    ListView_DeleteAllItems(hListControl);

    int c = Header_GetItemCount(ListView_GetHeader(hListControl)) - 1;
    while (c >= 0)
        ListView_DeleteColumn(hListControl, c--);

    ListView_SetExtendedListViewStyle(hListControl, exStyle);
    wchar_t buf[256];
    LVCOLUMN lvc = {0};
    lvc.mask     = LVCF_TEXT;
    lvc.fmt      = LVCFMT_LEFT;
    lvc.cx       = -1;
    lvc.pszText  = buf;
    wcscpy_s(buf, L"Original");
    ListView_InsertColumn(hListControl, 0, &lvc);
    wcscpy_s(buf, L"Encrypted");
    ListView_InsertColumn(hListControl, 1, &lvc);
    wcscpy_s(buf, L"Sync failures");
    ListView_InsertColumn(hListControl, 2, &lvc);

    for (auto it = g_pairs.begin(); it != g_pairs.end(); ++it)
    {
        if (it->m_syncDir == ToBeDeleted)
        {
            it->m_enabled = false;
            continue;
        }
        std::wstring origPath  = it->m_origPath;
        std::wstring cryptPath = it->m_cryptPath;
        LVITEM       lv        = {0};
        lv.mask                = LVIF_TEXT | LVIF_PARAM;
        lv.lParam              = distance(g_pairs.begin(), it);
        auto varBuf            = std::make_unique<WCHAR[]>(origPath.size() + 1);
        _tcscpy_s(varBuf.get(), origPath.size() + 1, origPath.c_str());
        lv.pszText = varBuf.get();
        lv.iItem   = ListView_GetItemCount(hListControl);
        int ret    = ListView_InsertItem(hListControl, &lv);
        if (ret >= 0)
        {
            lv.mask     = LVIF_TEXT;
            lv.iItem    = ret;
            lv.iSubItem = 1;
            varBuf      = std::make_unique<WCHAR[]>(cryptPath.size() + 1);
            lv.pszText  = varBuf.get();
            _tcscpy_s(lv.pszText, cryptPath.size() + 1, cryptPath.c_str());
            ListView_SetItem(hListControl, &lv);

            lv.iSubItem   = 2;
            lv.pszText    = buf;
            int failures  = GetFailuresFor(origPath);
            if (failures)
                swprintf_s(buf, L"%d", failures);
            else
                wcscpy_s(buf, L"none");
            ListView_SetItem(hListControl, &lv);
            ListView_SetCheckState(hListControl, ret, it->m_enabled);
        }
    }

    ListView_SetColumnWidth(hListControl, 0, LVSCW_AUTOSIZE_USEHEADER);
    ListView_SetColumnWidth(hListControl, 1, LVSCW_AUTOSIZE_USEHEADER);
    ListView_SetColumnWidth(hListControl, 2, LVSCW_AUTOSIZE_USEHEADER);
}

void COptionsDlg::DoListNotify(LPNMITEMACTIVATE lpNMItemActivate)
{
    if (lpNMItemActivate->hdr.code == NM_DBLCLK)
    {
        if ((lpNMItemActivate->iItem >= 0) && (lpNMItemActivate->iItem < static_cast<int>(g_pairs.size())))
        {
            DoPairEdit(lpNMItemActivate->iItem);
        }
    }
    else if (lpNMItemActivate->hdr.code == LVN_ITEMCHANGED)
    {
        HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
        DialogEnableWindow(IDC_DELETEPAIR, (ListView_GetSelectedCount(hListControl)) > 0);
        DialogEnableWindow(IDC_EDITPAIR, (ListView_GetSelectedCount(hListControl)) == 1);

        // No need to do following while initializing the list
        if (!m_listInit)
        {
            // process activate/deactvate
            if ((lpNMItemActivate->uNewState & LVIS_STATEIMAGEMASK) != 0)
            {
                LVITEM lv   = {};
                lv.iItem    = lpNMItemActivate->iItem;
                lv.iSubItem = 0;
                lv.mask     = LVIF_PARAM;
                ListView_GetItem(hListControl, &lv);
                if ((lv.lParam >= 0) && (lv.lParam < static_cast<int>(g_pairs.size())))
                {
                    auto& t     = g_pairs[lv.lParam];
                    t.m_enabled = ListView_GetCheckState(hListControl, lpNMItemActivate->iItem);
                    g_pairs.SavePairs();
                }
            }
        }
    }
}

int COptionsDlg::GetFailuresFor(const std::wstring& path) const
{
    int failures = 0;

    for (auto it = m_failures.cbegin(); it != m_failures.cend(); ++it)
    {
        if (it->first.size() > path.size())
        {
            if (it->first.substr(0, path.size()) == path)
            {
                if (it->first[path.size()] == '\\')
                    failures++;
            }
        }
    }
    return failures;
}

void COptionsDlg::SaveSettings()
{
    CRegStdString regStartWithWindows = CRegStdString(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CryptSync"));
    bool          bStartWithWindows   = !!SendDlgItemMessage(*this, IDC_AUTOSTART, BM_GETCHECK, 0, NULL);
    if (bStartWithWindows)
    {
        TCHAR buf[MAX_PATH * 4];
        GetModuleFileName(nullptr, buf, _countof(buf));
        std::wstring cmd = L"\"";
        cmd += std::wstring(buf);
        cmd += L"\" /tray";
        regStartWithWindows = cmd;
    }
    else
        regStartWithWindows.removeValue();

    // ReSharper disable once CppEntityAssignedButNoRead
    CRegStdString regIgnores(L"Software\\CryptSync\\Ignores", DEFAULT_IGNORES);
    auto          ignoreText = GetDlgItemText(IDC_IGNORE);
    regIgnores               = ignoreText.get();

    // ReSharper disable once CppEntityAssignedButNoRead
    CRegStdDWORD regInterval(L"Software\\CryptSync\\FullScanInterval", 60000 * 30);
    auto         intervalText = GetDlgItemText(IDC_INTERVAL);
    DWORD        intVal       = _wtoi(intervalText.get());
    if (intVal > 0)
        regInterval = intVal * 60000;

    HWND hListControl = GetDlgItem(*this, IDC_SYNCPAIRS);
    LVITEM lv           = {};
    lv.iSubItem         = 0;
    lv.mask             = LVIF_PARAM;

    for (auto iItem = 0; iItem < ListView_GetItemCount(hListControl); iItem++)
    {
        lv.iItem = iItem;
        ListView_GetItem(hListControl, &lv);
        g_pairs[lv.lParam].m_enabled = ListView_GetCheckState(hListControl, iItem);
    }

    g_pairs.SavePairs();

    CIgnores::Instance().Reload();
}
