// CThreadSafe - Thread safe set and map.

// Still need to use CAutoWriteLock / CAutoReadLock 
// if there is a need to protect a series of set / map
// operations (in a loop, for example)

// Copyright (C) 2024 - Stefan Kueng

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

#include <windows.h>
#include <set>
#include <map>
#include "ReaderWriterLock.h"

template <typename T>
class CThreadSafeSet : std::set<T>
{
public:
    CThreadSafeSet()
    {
    }

    virtual ~CThreadSafeSet()
    {
    }

    virtual CThreadSafeSet<T>::const_iterator cbegin() const
    {
        CAutoReadLock locker(m_Setguard);
        auto          it = std::set<T>::cbegin();
        return it;
    }

    virtual CThreadSafeSet<T>::const_iterator cend() const
    {
        CAutoReadLock locker(m_Setguard);
        auto          it = std::set<T>::cend();
        return it;
    }

    // Insert an element into the set
    virtual std::pair<typename CThreadSafeSet<T>::iterator, bool> insert(const T& value)
    {
        CAutoWriteLock locker(m_Setguard);
        auto           result = std::set<T>::insert(value);
        return result;
    }

    // Remove an element from the set
    virtual size_t erase(const T& value)
    {
        CAutoWriteLock locker(m_Setguard);
        // auto count = std::set<T>::erase(value);
        size_t         count = std::set<T>::erase(value);
        return count;
    }

    virtual void erase(const CThreadSafeSet<T>::const_iterator& position)
    {
        CAutoWriteLock locker(m_Setguard);
        std::set<T>::erase(position);
        return;
    }

    // Find an element in the set
    virtual CThreadSafeSet<T>::iterator find(const T& value) const
    {
        CAutoReadLock locker(m_Setguard);
        auto          found = std::set<T>::find(value);
        return found;
    }

    // Get the size of the set
    virtual size_t size() const
    {
        CAutoReadLock locker(m_Setguard);
        size_t        s = std::set<T>::size();
        return s;
    }

    // Is set empty
    virtual bool empty() const
    {
        return size() == 0;
    }

    // Clear the set
    virtual void clear()
    {
        CAutoWriteLock locker(m_Setguard);
        std::set<T>::clear();
    }

    virtual CThreadSafeSet<T> operator=(const std::set<T>& rhs)
    {
        CAutoWriteLock locker(m_Setguard);
        std::set<T>::operator=(rhs);
        return *this;
    }

private:
    mutable CReaderWriterLock m_Setguard;
};

template <typename Key, typename T>
class CThreadSafeMap : std::map<Key, T>
{
public:
    CThreadSafeMap()
    {
    }

    virtual ~CThreadSafeMap()
    {
    }

    virtual CThreadSafeMap<Key, T>::const_iterator cbegin() const
    {
        CAutoReadLock locker(m_Mapguard);
        auto          it = std::map<Key, T>::cbegin();
        return it;
    }

    virtual CThreadSafeMap<Key, T>::const_iterator cend() const
    {
        CAutoReadLock locker(m_Mapguard);
        auto          it = std::map<Key, T>::cend();
        return it;
    }

    // Insert an element into the set
    virtual std::pair<typename CThreadSafeMap<Key, T>::iterator, bool> insert(const std::pair<Key, T>& value)
    {
        CAutoWriteLock locker(m_Mapguard);
        auto           result = std::map<Key, T>::insert(value);
        return result;
    }

    // Remove an element from the map
    virtual size_t erase(const Key& key)
    {
        CAutoWriteLock locker(m_Mapguard);
        size_t         count = std::map<Key, T>::erase(key);
        return count;
    }

    virtual CThreadSafeMap<Key, T>::iterator erase(const CThreadSafeMap<Key, T>::const_iterator& position)
    {
        CAutoWriteLock locker(m_Mapguard);
        auto it = std::map<Key, T>::erase(position);
        return it;
    }

    // Find an element in the map
    virtual CThreadSafeMap<Key, T>::const_iterator find(const Key& key) const
    {
        CAutoReadLock locker(m_Mapguard);
        auto          found = std::map<Key, T>::find(key);
        return found;
    }

    // Get the size of the map
    virtual size_t size() const
    {
        CAutoReadLock locker(m_Mapguard);
        size_t        s = std::map<Key, T>::size();
        return s;
    }

    // Is map empty
    virtual bool empty() const
    {
        return size() == 0;
    }

    // Clear the map
    virtual void clear()
    {
        CAutoWriteLock locker(m_Mapguard);
        std::map<Key, T>::clear();
    }

    virtual CThreadSafeMap<Key, T> operator=(const std::map<Key, T>& rhs)
    {
        CAutoWriteLock locker(m_Mapguard);
        std::map<Key, T>::operator=(rhs);
        return *this;
    }

private:
    mutable CReaderWriterLock m_Mapguard;
};
