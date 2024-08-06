// CryptSync - A folder sync tool with encryption

// Copyright (C) 2012, 2014-2016, 2021 - Stefan Kueng

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

#pragma once

#include "ReaderWriterLock.h"
#include "SmartHandle.h"
#include "StringUtils.h"
#include <string>
#include <set>
#include <map>

constexpr auto READ_DIR_CHANGE_BUFFER_SIZE = 65536/*4096*/;
constexpr auto MAX_CHANGED_PATHS           = 4000;

/**
 * \ingroup Utils
 * Watches the file system for changes.
 *
 * When a CPathWatcher object is created, a new thread is started which
 * waits for file system change notifications.
 * To add folders to the list of watched folders, call \c AddPath().
 *
 * The folders are watched recursively. To prevent having too many folders watched,
 * children of already watched folders are automatically removed from watching.
 */
class CPathWatcher
{
public:
    CPathWatcher();
    ~CPathWatcher();

    /**
     * Adds a new path to be watched. The path \b must point to a directory.
     * If the path is already watched because a parent of that path is already
     * watched recursively, then the new path is just ignored and the method
     * returns false.
     */
    bool AddPath(const std::wstring& path, long long id = 0);
#if 0
    /**
     * Removes a path and all its children from the watched list.
     */
    bool RemovePath(const std::wstring& path);
#endif

    /**
     * Commit path changes and trigger watching new list.
     */
    void CommitPathChanges(void);

    /**
     * Removes all watched paths
     */
    void ClearPaths()
    {
        CAutoWriteLock locker(m_guard);
        watchedPaths.clear();
        // m_hCompPort.CloseHandle(); // Commented as this may stop notifications for all pairs, risking missing file deletes and other changes
    }

#if 0
    /**
     * Returns the number of recursively watched paths.
     */
    size_t GetNumberOfWatchedPaths() const { return watchedPaths.size(); }
#endif

    /**
     * Returns all changed paths since the last call to GetChangedPaths
     */
    std::set<std::wstring> GetChangedPaths();

    /**
     * Stops the watching thread.
     */
    void Stop();

private:
    static unsigned int __stdcall ThreadEntry(void* pContext);
    void WorkerThread();

    void ClearInfoMap();

private:
    CReaderWriterLock  m_guard;
    CAutoGeneralHandle m_hThread;
    CAutoGeneralHandle m_hCompPort;
    volatile LONG      m_bRunning;

#define FREE_PDI  ((DWORD)-1L)
#define ALLOC_PDI ((DWORD)-2L)
#define STOPPING  ((DWORD)-3L)

    // std::set<std::wstring> watchedPaths; ///< list of watched paths.
    // v list of watched paths after CPathUtils::AdjustForMaxPath is done
    std::map<std::wstring, long long> watchedPaths; 
    std::map<std::wstring, long long> uncommittedWatchedPaths;

    /**
     * Helper class: provides information about watched directories.
     */
    class CDirWatchInfo
    {
    private:
        CDirWatchInfo()                       = delete;
        CDirWatchInfo(const CDirWatchInfo& i) = delete;
        CDirWatchInfo& operator=(const CDirWatchInfo& rhs) = delete;

    public:
        CDirWatchInfo(CAutoFile&& hDir, const std::wstring& directoryName);
        ~CDirWatchInfo();

        bool CloseDirectoryHandle();

        CAutoFile    m_hDir;                                ///< handle to the directory that we're watching
        std::wstring m_dirName;                             ///< the directory that we're watching
        __declspec(align(sizeof(DWORD)))                    ///< buffer must be DWORD-aligned as per doc
        CHAR         m_buffer[READ_DIR_CHANGE_BUFFER_SIZE]; ///< buffer for ReadDirectoryChangesW
        OVERLAPPED   m_overlapped;
        std::wstring m_dirPath; ///< the directory name we're watching with a backslash at the end
    };

    class CWatchInfoMap : std::map<std::wstring, CDirWatchInfo*, ci_lessW>
    {
    private:
        // CWatchInfoMap() = delete;
        CWatchInfoMap(const CDirWatchInfo& i)              = delete;
        CWatchInfoMap& operator=(const CWatchInfoMap& rhs) = delete;

    public:
        ~CWatchInfoMap();
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::map; // inherit constructors
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::find;
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::end;
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::begin;
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::empty;
        using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::operator[];
        // using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::operator=;
        // using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::erase;
        // using std::map<std::wstring, CDirWatchInfo*, ci_lessW>::clear;
        void                                  CloseDirHandle(const std::wstring p);
        CPathWatcher::CWatchInfoMap::iterator CloseDirHandle(CPathWatcher::CWatchInfoMap::iterator it);
        void                                  clear();
    };

    bool                             VerifywatchInfoMap();
    CWatchInfoMap                    m_watchInfoMap;

    std::set<std::wstring>           m_changedPaths;
};
