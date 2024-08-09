// CryptSync - A folder sync tool with encryption

// Copyright (C) 2012-2016, 2021, 2024 - Stefan Kueng

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
#include "PathWatcher.h"
#include "DebugOutput.h"
#include "PathUtils.h"

#include <Dbt.h>
#include <process.h>
#ifdef _DEBUG
#include <comdef.h>
#endif

CPathWatcher::CPathWatcher()
    : m_hCompPort(nullptr)
    , m_bRunning(TRUE)
{
    // enable the required privileges for this process

    LPCTSTR arPrivelegeNames[] = {SE_BACKUP_NAME,
                                  SE_RESTORE_NAME,
                                  SE_CHANGE_NOTIFY_NAME};

    for (int i = 0; i < _countof(arPrivelegeNames); ++i)
    {
        CAutoGeneralHandle hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, hToken.GetPointer()))
        {
            TOKEN_PRIVILEGES tp = {1};

            if (LookupPrivilegeValue(nullptr, arPrivelegeNames[i], &tp.Privileges[0].Luid))
            {
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            }
        }
    }

    unsigned int threadId = 0;
    m_hThread             = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, ThreadEntry, this, 0, &threadId));
}

CPathWatcher::~CPathWatcher()
{
    Stop();
    // ClearInfoMap() should already have been done by thread...
    ClearInfoMap();
}

void CPathWatcher::Stop()
{
    InterlockedExchange(&m_bRunning, FALSE);
    if (m_hCompPort)
    {
        if (PostQueuedCompletionStatus(m_hCompPort, STOPPING, NULL, nullptr) == 0)
        {
            _com_error comError(::GetLastError());
            LPCTSTR    comErrorText = comError.ErrorMessage();
            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": PostQueuedCompletionStatus STOPPING failed (%s)\n"), comErrorText);
        }
        // m_hCompPort.CloseHandle(); // Commented, will be done in thread when it calls ClearInfoMap()
    }

    if (m_hThread)
    {
        // the background thread sleeps for 200ms,
        // so lets wait for it to finish for 1000 ms.

        WaitForSingleObject(m_hThread, 1000);
        m_hThread.CloseHandle();
    }
}

#if 0
bool CPathWatcher::RemovePath(const std::wstring& path)
{
    CAutoWriteLock locker(m_guard);

    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": RemovePath for %s\n"), path.c_str());
    bool bRet = (watchedPaths.erase(CPathUtils::AdjustForMaxPath(path)) != 0);
    // m_hCompPort.CloseHandle(); // Commented as this may stop notifications for all pairs, risking missing file deletes and other changes
    return bRet;
}
#endif

bool CPathWatcher::AddPath(const std::wstring& path, long long id)
{
    CAutoWriteLock locker(m_guard);
    auto insertResult = uncommittedWatchedPaths.insert({CPathUtils::AdjustForMaxPath(path), id});
#ifdef _DEBUG
    if (insertResult.second)
    {
        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": AddPath for %s\n"), path.c_str());
    }
    else
    {
        if (insertResult.first->second != id)
        {
            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": AddPath same path %s used in id %d and %d\n"), path.c_str(), insertResult.first->second, id);
        }
    }
#endif
    // m_hCompPort.CloseHandle(); // Commented as this may stop notifications for all pairs, risking missing file deletes and other changes
    return insertResult.second;
}

void CPathWatcher::CommitPathChanges()
{
    CAutoWriteLock locker(m_guard);
    watchedPaths = uncommittedWatchedPaths;
    uncommittedWatchedPaths.clear();
    if (m_hCompPort)
    {
        if (PostQueuedCompletionStatus(m_hCompPort, ALLOC_PDI, NULL, nullptr) == 0)
        {
            _com_error comError(::GetLastError());
            LPCTSTR    comErrorText = comError.ErrorMessage();
            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": PostQueuedCompletionStatus ALLOC_PDI failed (%s)\n"), comErrorText);
        }
    }
}

unsigned int CPathWatcher::ThreadEntry(void* pContext)
{
    static_cast<CPathWatcher*>(pContext)->WorkerThread();
    return 0;
}

void CPathWatcher::WorkerThread()
{
    DWORD          lasterr;
    DWORD          numBytes;
    CDirWatchInfo* pdi = nullptr;
    LPOVERLAPPED   lpOverlapped;
    bool           bCheckHandles = false;
    while (m_bRunning)
    {
        if (VerifywatchInfoMap())
        {
            // Not watching anything
            ClearInfoMap();
        }

        // Note that watchedPaths may become empty as we remove
        // some paths during error handling. Periodically, TrayWindow
        // will add back the paths it wants to be monitored, in hope
        // they will eventually be (the error situation somehow
        // got resolved).
        if (!watchedPaths.empty())
        {
            // Sets data to GetQueuedCompletionStatus() "successful" 
            // values in case bCheckHandles is true.
            SetLastError(ERROR_SUCCESS);
            numBytes = 0;
            pdi      = nullptr;
            lpOverlapped = nullptr;
            if (bCheckHandles == true || !m_hCompPort || !GetQueuedCompletionStatus(m_hCompPort,
                                                           &numBytes,
                                                           reinterpret_cast<PULONG_PTR>(&pdi),
                                                           &lpOverlapped,
                                                           INFINITE))
            {
                if (!m_bRunning)
                    return;

                // Possibly error retrieving changes
                lasterr = GetLastError();

#ifdef _DEBUG
                if (m_hCompPort && !bCheckHandles)
                {
                    _com_error comError(lasterr);
                    LPCTSTR    comErrorText = comError.ErrorMessage();
                    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": GetQueuedCompletionStatus failed (%s) on directory %s\n"), comErrorText, pdi->m_dirPath.c_str());
                }
#endif
                /*
                * From https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesexw: 
                * If the network redirector or the target file system does 
                * not support this operation, the function fails with ERROR_INVALID_FUNCTION.
                */
                if ((m_hCompPort) && (lasterr == ERROR_INVALID_FUNCTION))
                {
                    if (pdi)
                    {
                        if (pdi->m_hDir.IsValid())
                        {
                            pdi->CloseDirectoryHandle();
                        }
                        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": Device for %s does not support ReadDirectoryChangesW() - file change notification impossible\n"), pdi->m_dirName.c_str());
                        CAutoWriteLock lockerW(m_guard);
                        pdi->m_bNotSupported = true;
                        // We do not erase this entry, we just mark it as "not supported". This
                        // avoids constantly trying to open the handle and calling ReadDirectoryChangesW()
                        // at each commit
                        // watchedPaths.erase(pdi->m_dirName);
                    }
                    else
                    {
                        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": A device does not support ReadDirectoryChangesW() - file change notification impossible\n"));
                    }
                    continue;
                }
                /*
                * From https://stackoverflow.com/questions/14801950/getqueuedcompletionstatusex-readdirectorychangesw
                * We should handle the ERROR_NOTIFY_ENUM_DIR error code (possibly STATUS_NOTIFY_ENUM_DIR too
                * if there is indeed a bug in Windows).
                */
                if ((m_hCompPort) && (lasterr == ERROR_NOTIFY_ENUM_DIR))
                {
                    if (pdi)
                    {
                        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": ERROR_NOTIFY_ENUM_DIR on %s\n"), pdi->m_dirName.c_str());
                        //CAutoWriteLock lockerW(m_guard);
                        //pdi->m_bNotSupported = true;
                        // We do not erase this entry, we just mark it as "not supported". This
                        // avoids constantly trying to open the handle and calling ReadDirectoryChangesW()
                        // at each commit
                        // watchedPaths.erase(pdi->m_dirName);
                    }
                    else
                    {
                        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": ERROR_NOTIFY_ENUM_DIR on unknow path\n"));
                    }
                    assert(0);  // Need to confirm how to handle this case.
                    continue;
                }

                // ERROR_INVALID_HANDLE returned on closing/closed handle 
                // ERROR_OPERATION_ABORTED when CancelIo() is done
                if ((m_hCompPort) && (lasterr != ERROR_SUCCESS) && (lasterr != ERROR_INVALID_HANDLE) && (lasterr != ERROR_OPERATION_ABORTED))
                {
                    // Close all reference dir handles and m_hCompPort.
                    // They will be re-created below.
                    ClearInfoMap();
                }
                {
                    CAutoReadLock locker(m_guard);
                    for (auto p = watchedPaths.cbegin(); p != watchedPaths.cend();)
                    {
                        bool           bAddToIoCompletionPort = FALSE;
                        auto           pDirInfoIter           = m_watchInfoMap.find(p->first);
                        CDirWatchInfo* pDirInfo               = nullptr;
                        if (pDirInfoIter != m_watchInfoMap.cend())
                        {
                            pDirInfo = pDirInfoIter->second;
                        }
                        if (pDirInfo != nullptr)
                        {
                            if (pDirInfo->m_bNotSupported)
                            {
                                p++;
                                continue;
                            }
                            if (pDirInfo->m_hDir.IsValid())
                            {
                                // Confirm directory handle is still valid for Windows
                                BY_HANDLE_FILE_INFORMATION FileInformation;
                                if (GetFileInformationByHandle(pDirInfo->m_hDir, &FileInformation) == 0)
                                {
#ifdef _DEBUG
                                    {
                                        _com_error comError(GetLastError());
                                        LPCTSTR    comErrorText = comError.ErrorMessage();
                                        CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": GetFileInformationByHandle on %s directory failed (%s) \n"), p->first.c_str(), comErrorText);
                                    }
#endif
                                    pDirInfo->CloseDirectoryHandle();
                                }
                            }
                        }
                        if (pDirInfo == nullptr || pDirInfo->m_hDir == INVALID_HANDLE_VALUE)
                        {
                            CAutoFile hDir = CreateFile(p->first.c_str(),
                                                        FILE_LIST_DIRECTORY,
                                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                        nullptr, // security attributes
                                                        OPEN_EXISTING,
                                                        FILE_FLAG_BACKUP_SEMANTICS | // required privileges: SE_BACKUP_NAME and SE_RESTORE_NAME.
                                                            FILE_FLAG_OVERLAPPED,
                                                        nullptr);
                            if (!hDir)
                            {
#ifdef _DEBUG
                                {
                                    _com_error comError(GetLastError());
                                    LPCTSTR    comErrorText = comError.ErrorMessage();
                                    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": CreateFile on %s directory failed (%s) \n"), p->first.c_str(), comErrorText);
                                }
#endif
                                // this could happen if a watched folder has been removed/renamed
                                // m_hCompPort.CloseHandle();  m_hCompPort is still valid for the other dir handles
                                CAutoWriteLock lockerW(m_guard);
                                m_watchInfoMap.CloseDirHandle(p->first); // Should do nothing
                                p = watchedPaths.erase(p);               // Get next p from erase() to avoid invalidating the iterator
                                continue;
                            }
                            else
                            {
                                bAddToIoCompletionPort = TRUE;
                            }
                            if (pDirInfo == nullptr)
                            {
                                pDirInfo = new CDirWatchInfo(std::move(hDir), p->first);
                                // auto upDirInfo = std::make_unique<CDirWatchInfo>(std::move(hDir), p->c_str());
                                // pDirInfo       = upDirInfo.release();
                            }
                            else
                            {
                                pDirInfo->m_hDir = std::move(hDir);
                            }
                        } // pDirInfo == nullptr || pDirInfo->m_hDir == INVALID_HANDLE_VALUE

                        {
                            CAutoWriteLock lockerW(m_guard);
                            m_watchInfoMap[p->first] = pDirInfo;
                        }

                        if (bAddToIoCompletionPort)
                        {
#ifdef _DEBUG
                            {
                                WCHAR FileSystemNameBuffer[60];
                                FileSystemNameBuffer[(sizeof(FileSystemNameBuffer) / sizeof(sizeof(FileSystemNameBuffer[0]))) - 1] = 0;
                                if (GetVolumeInformationByHandleW(pDirInfo->m_hDir, NULL, 0, NULL, NULL, NULL, FileSystemNameBuffer, sizeof(FileSystemNameBuffer) - 1) != 0)
                                    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": Directory %s on file system \"%s\"\n"), p->first.c_str(), FileSystemNameBuffer);
                            }
#endif
                            m_hCompPort = CreateIoCompletionPort(pDirInfo->m_hDir, m_hCompPort, reinterpret_cast<ULONG_PTR>(pDirInfo), 0);
                            if (m_hCompPort == NULL)
                            {
#ifdef _DEBUG
                                {
                                    _com_error comError(GetLastError());
                                    LPCTSTR    comErrorText = comError.ErrorMessage();
                                    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": CreateIoCompletionPort on %s directory failed (%s) \n"), p->first.c_str(), comErrorText);
                                }
#endif
                                CAutoWriteLock lockerW(m_guard);
                                // ClearInfoMap();
                                m_watchInfoMap.CloseDirHandle(p->first.c_str());
                                p = watchedPaths.erase(p); // Get next p from erase() to avoid invalidating the iterator
                                continue;
                            }
                            SecureZeroMemory(pDirInfo->m_buffer, sizeof(pDirInfo->m_buffer));
                            SecureZeroMemory(&pDirInfo->m_overlapped, sizeof(pDirInfo->m_overlapped));
                            if (!ReadDirectoryChangesW(pDirInfo->m_hDir,
                                                       pDirInfo->m_buffer,
                                                       READ_DIR_CHANGE_BUFFER_SIZE,
                                                       TRUE,
                                                       FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                                       &numBytes, // not used
                                                       &pDirInfo->m_overlapped,
                                                       nullptr // no completion routine!
                                                               /*,ReadDirectoryNotifyExtendedInformation
                                                                *  Extra parameter for the "Ex" function ReadDirectoryChangesExW
                                                                *  but it only supported on NTFS
                                                                */
                                                       ))
                            {
#ifdef _DEBUG
                                {
                                    _com_error comError(GetLastError());
                                    LPCTSTR    comErrorText = comError.ErrorMessage();
                                    CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": ReadDirectoryChanges on %s directory failed (%s) \n"), p->first.c_str(), comErrorText);
                                }
#endif
                                CAutoWriteLock lockerW(m_guard);
                                m_watchInfoMap.CloseDirHandle(p->first.c_str());
                                p                         = watchedPaths.erase(p); // Get next p from erase() to avoid invalidating the iterator
                                pDirInfo->m_bNotSupported = true;
                                continue;
                            } // !ReadDirectoryChangesW()
                            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": watching path %s\n"), p->first.c_str());
                        } // if (bAddToIoCompletionPort)
                        p++;
                    } // for all watched paths
                }
                bCheckHandles = false;
            }
            else
            {
                if (!m_bRunning)
                    return;
                if (lpOverlapped == NULL)
                {
                    // Received a self-posted PostQueuedCompletionStatus() message
                    switch (numBytes)
                    {
                        case STOPPING:
                            // Should never reach here as m_bRunning is checked above
                            assert(false);
                            return;
                        case FREE_PDI:
                        {
                            std::wstring* upDirName = reinterpret_cast<std::wstring*>(pdi);
                            CAutoWriteLock locker(m_guard);
                            m_watchInfoMap.CloseDirHandle(upDirName->c_str());
                            delete upDirName;
                        }
                            continue;
                        case ALLOC_PDI:
                            bCheckHandles = true;
                            continue;
                    }
                    assert(false);
                }
                // NOTE: the longer this code takes to execute until ReadDirectoryChangesW
                // is called again, the higher the chance that we miss some
                // changes in the file system!
                if (pdi)
                {
                    // PFILE_NOTIFY_EXTENDED_INFORMATION gives benefit of knowing if notification is for a directory,
                    // but it is only supported for NTFS file systems.
                    PFILE_NOTIFY_INFORMATION pnotify = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(pdi->m_buffer);
                    DWORD                             nOffset = 0;
                    if (numBytes != 0)
                    {
                        do
                        {
                            pnotify           = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(reinterpret_cast<LPBYTE>(pnotify) + nOffset);
                            size_t bufferSize = pdi->m_dirPath.size() + (pnotify->FileNameLength / sizeof(pnotify->FileName[0])) + 1;
                            auto   buf        = std::make_unique<wchar_t[]>(bufferSize);
                            nOffset           = pnotify->NextEntryOffset;
                            auto action       = pnotify->Action;

                            if (reinterpret_cast<ULONG_PTR>(pnotify) - reinterpret_cast<ULONG_PTR>(pdi->m_buffer) > READ_DIR_CHANGE_BUFFER_SIZE)
                                break;

                            wcscpy_s(buf.get(), bufferSize, pdi->m_dirPath.c_str());

                            // pnotify->FileName is not null terminated, the second argument to wcsncat_s limits the number of characters
                            // concatenated and the last parameter forces truncation; STRUNCATE, the expected return value since buf is allocated
                            // accordingly, is a valid return value.
                            // errno_t err     = wcsncat_s(buf.get() + pdi->m_dirPath.size(), min(pnotify->FileNameLength / sizeof(pnotify->FileName[0]) + 1, bufferSize - pdi->m_dirPath.size()), pnotify->FileName, _TRUNCATE);
                            // Above code may do a one-wchar_t source buffer read overrun on m_buffer, we can either declare m_buffer as "READ_DIR_CHANGE_BUFFER_SIZE + sizeof(wchar_t)" bytes
                            // or use memmove_s() to prevent source buffer overrun

                            errno_t err         = wmemmove_s(buf.get() + pdi->m_dirPath.size(),
                                                             min(pnotify->FileNameLength / sizeof(pnotify->FileName[0]), bufferSize - pdi->m_dirPath.size()),
                                                             pnotify->FileName,
                                                             pnotify->FileNameLength / sizeof(pnotify->FileName[0]));

                            buf[bufferSize - 1] = 0;
                            if (err != 0)
                            {
                                continue;
                            }
#ifdef _DEBUG
                            {
                                const static wchar_t* const szActionNames[] = {
                                    L"ADDED",
                                    L"REMOVED",
                                    L"MODIFIED",
                                    L"RENAMED_OLD_NAME",
                                    L"RENAMED_NEW_NAME"};
                                wchar_t szActionName[100];
                                szActionName[(sizeof(szActionName) / sizeof(szActionName[0])) - 1] = 0;
                                if (action >= 1 && action < (sizeof(szActionNames) / sizeof(szActionNames[0])))
                                {
                                    wcsncpy_s(szActionName, szActionNames[action - 1], (sizeof(szActionName) / sizeof(szActionName[0])) - 1);
                                }
                                else
                                {
                                    swprintf_s(szActionName, (sizeof(szActionName) / sizeof(szActionName[0])) - 1, L"unknown action %d", action);
                                }
                                CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": change notification for %s (%s)\n"), buf.get(), szActionName);
                                if (0 == _wcsicmp(buf.get(), L"\\\\?\\C:\\Users\\Daniel\\source\\repos\\dansyl1\\CryptSync\\.vs\\CryptSync\\FileContentIndex\\4b128779-5982-4733-a83d-356ffc1e6545.vsidx"))
                                    DebugBreak();
                            }
#endif

#ifdef SUPPORT_READDIRECTORYCHANGESEXW
                            // We don't care about changes to directories, unless one is removed. An addition will be handled
                            // by the notification for files added/modified under it. A directory modification is irrelevant
                            // to cryptsync. A directory rename could have a specific handling, renaming the corresponding
                            // directory instead of re-encrypting/decrypting, but this is not implemented. A file rename 
                            // must be re-encrypted/decrypted since the filename is in the .7z archive
                            if (!(pnotify->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || action == FILE_ACTION_REMOVED)
                            {
                                {
                                    CAutoWriteLock locker(m_guard);
                                    m_changedPaths.insert(std::wstring(buf.get()));
                                }
                            }
#else
                            {
                                CAutoWriteLock locker(m_guard);
                                m_changedPaths.insert(std::wstring(buf.get()));
                            }
#endif
                        } while (nOffset);
                    }
                    else
                    { // numBytes == 0
#ifdef _DEBUG
                        if (m_hCompPort)
                        {
                            _com_error comError(GetLastError());
                            LPCTSTR    comErrorText = comError.ErrorMessage();
                            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": GetQueuedCompletionStatus returned zero numBytes (%s) for watched folder \"%s\"\n"), comErrorText, pdi->m_dirPath.c_str());
                            if (!pdi->m_hDir.IsValid())
                            {
                                CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": GetQueuedCompletionStatus directory handle for \"%s\" closed\n"), pdi->m_dirPath.c_str());
                            }
                        }
#endif
                    }
                    SecureZeroMemory(pdi->m_buffer, sizeof(pdi->m_buffer));
                    SecureZeroMemory(&pdi->m_overlapped, sizeof(pdi->m_overlapped));
                    if (!ReadDirectoryChangesW(pdi->m_hDir,
                                               pdi->m_buffer,
                                               READ_DIR_CHANGE_BUFFER_SIZE,
                                               TRUE,
                                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                               /*
                                                    Warning: including FILE_NOTIFY_CHANGE_ATTRIBUTES below would
                                                             result in notifications when we change the "index"
                                                             on target file or "archive" on source
                                               */
                                               &numBytes, // not used
                                               &pdi->m_overlapped, 
                                               nullptr // no completion routine!
                                               /*,ReadDirectoryNotifyExtendedInformation
                                                *  Extra parameter for the "Ex" function ReadDirectoryChangesExW
                                                *  but it only supported on NTFS
                                               */ ))
                    {
                        // Since the call to ReadDirectoryChangesW failed, just
                        // wait a while. We don't want to have this thread
                        // running using 100% CPU if something goes completely
                        // wrong.
#ifdef _DEBUG
                        {
                            _com_error comError(GetLastError());
                            LPCTSTR    comErrorText = comError.ErrorMessage();
                            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": ReadDirectoryChangesW failed (%s) for watched folder \"%s\"\n"), comErrorText, pdi->m_dirPath.c_str());
                        }
#endif
                        pdi->CloseDirectoryHandle();
                        // Set flag so that directory handle will be re-open on next loop and ReadDirectory done 
                        bCheckHandles = true;
                        Sleep(200);
                    } // !ReadDirectoryChangesW()
                } // if (pdi)
            }
        } // if (!watchedPaths.empty())
        else
        {
            // watchedPaths.empty()
            Sleep(200);
        }
    } // while (m_bRunning)
}

void CPathWatcher::ClearInfoMap()
{
    CAutoWriteLock locker(m_guard);
    m_watchInfoMap.clear();  // clear() method will delete the CDirWatchInfo
    if (m_hCompPort)
    {
        CancelIo(m_hCompPort);
    }
    m_hCompPort.CloseHandle();
}

std::set<std::wstring> CPathWatcher::GetChangedPaths()
{
    CAutoWriteLock         locker(m_guard);
    std::set<std::wstring> ret = m_changedPaths;
    m_changedPaths.clear();
    return ret;
}

bool CPathWatcher::VerifywatchInfoMap()
{
    CAutoReadLock locker(m_guard);
    bool          bOkToClearInfoMap = false;

    if (!m_watchInfoMap.empty())
    {
        CDirWatchInfo* pDirInfo = nullptr;
        bOkToClearInfoMap       = true;

        for (auto I = m_watchInfoMap.cbegin(); I != m_watchInfoMap.cend(); I++)
        {
            pDirInfo = I->second;
            if (pDirInfo != nullptr && pDirInfo->m_hDir.IsValid())
            { // We have required information to allow watching this directory

                if (watchedPaths.find(I->first.c_str()) == watchedPaths.end())
                {
                    // not a path we should be watching
                    // Currently watching it, CloseDirectoryHandle will call CancelIo and trigger
                    // GetQueuedCompletionStatus() to complete, if pending.
                    pDirInfo->CloseDirectoryHandle();
                }
                else
                {
                    // This is a directory we continue watching, InfoMap still needed
                    bOkToClearInfoMap = false;
                    // continue, and not break so we can check if there are directories we shoud no longer monitor
                    continue;  
                }
            } // if (pDirInfo != nullptr && pDirInfo->m_hDir.IsValid())
        }     // for
    }         // not empty
    return (bOkToClearInfoMap);
#if 0
    // Path that are to be watched but aren't are added back
    // by Commit method
    bool bAlloc_pdi_posted = false;
    if (!watchedPaths.empty())
    {
        for (auto I = watchedPaths.begin(); I != watchedPaths.end(); I++)
        {
            if (m_watchInfoMap.find(I->c_str()) == m_watchInfoMap.end())
            {
                // path we should be watching
                if (m_hCompPort)
                {
                    // Currently possibly blocked watching other paths. 
                    // Trigger GetQueuedCompletionStatus()
                    // to unblock and allocate pdi(s)
                    if (!bAlloc_pdi_posted)
                    {
                        PostQueuedCompletionStatus(m_hCompPort, (DWORD)ALLOC_PDI, NULL, nullptr);
                        bAlloc_pdi_posted = true;
                    }
                }
            }
        }
    }
#endif
}

CPathWatcher::CDirWatchInfo::CDirWatchInfo(CAutoFile&& hDir, const std::wstring& directoryName)
    : m_hDir(std::move(hDir))
    , m_dirName(directoryName)
{
    SecureZeroMemory(m_buffer, sizeof(m_buffer));
    SecureZeroMemory(&m_overlapped, sizeof(m_overlapped));
    m_dirPath = m_dirName;
    if (m_dirPath.at(m_dirPath.size() - 1) != '\\')
        m_dirPath += _T("\\");
    m_bNotSupported = false;
}

CPathWatcher::CDirWatchInfo::~CDirWatchInfo()
{
    CloseDirectoryHandle();
}

bool CPathWatcher::CDirWatchInfo::CloseDirectoryHandle()
{
    if (m_hDir)
    {
        // DWORD NumberOfBytesTransferred;
        if (CancelIoEx(m_hDir, &m_overlapped) == 0)
        {
            _com_error comError(GetLastError());
            LPCTSTR    comErrorText = comError.ErrorMessage();
            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": CancelIoEx failed (%s)\n"), comErrorText);
        }
#if 0
        while (GetOverlappedResult(m_hDir, &m_overlapped, &NumberOfBytesTransferred, false) == 0)
        {
            _com_error comError(GetLastError());
            LPCTSTR    comErrorText = comError.ErrorMessage();
            CTraceToOutputDebugString::Instance()(_T(__FUNCTION__) _T(": GetOverlappedResult failed (%s)\n"), comErrorText);
            Sleep(200);
        }
#endif
    }

    return m_hDir.CloseHandle();
}

CPathWatcher::CWatchInfoMap::~CWatchInfoMap()
{
    CPathWatcher::CWatchInfoMap::clear();
}

void CPathWatcher::CWatchInfoMap::clear()
{
    // if m_hCompPort is valid then pdi that we delete below will still
    // be used and returned by GetQueuedCompletionStatus()
    // 
    // TO DO: add following statement
    // assert(!m_hCompPort);
    if (!empty())
    {
        for (auto I = begin(); I != end(); ++I)
        {
            CPathWatcher::CDirWatchInfo* info = I->second;
            // const std::wstring pwstring            = I->first;
            I->second                         = nullptr;
            // delete pwstring;
            delete info;
        }
        ((std::map<std::wstring, CDirWatchInfo*, ci_lessW>*)this)->clear();
    }
}

CPathWatcher::CWatchInfoMap::iterator CPathWatcher::CWatchInfoMap::CloseDirHandle(CPathWatcher::CWatchInfoMap::iterator it)
{
    if (it != end())
    {
        CPathWatcher::CDirWatchInfo* info = it->second;
        // info may still be used by GetQueuedCompletionStatus() so
        // we just close its m_hDir. m_bNotSupported, for example.
        // it->second                        = nullptr;
        // delete info;
        info->CloseDirectoryHandle();
        it++;
    }

    return it;
}

void CPathWatcher::CWatchInfoMap::CloseDirHandle(const std::wstring p)
{
    if (!empty())
    {
        auto I = find(p);
        if (I != end())
        {
            CPathWatcher::CDirWatchInfo* info = I->second;
            // info still be used by GetQueuedCompletionStatus() so
            // we just close its m_hDir. m_bNotSupported, for example.
            // I->second                         = nullptr;
            // delete info;
            info->CloseDirectoryHandle();
        }
    }
}
