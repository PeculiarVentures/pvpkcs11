#pragma once

#include <algorithm>
#include "../stdafx.h"

template<class T>
class Collection
{
public:
	Collection();
	~Collection();

	size_t count();
	void add(T item);
	void remove(T item);
	T items(size_t index);
	void clear();

protected:
	std::vector<T> _items;

};

template<class T>
Collection<T>::Collection()
{
	this->_items = std::vector<T>();
}

template<class T>
Collection<T>::~Collection()
{

}

template<class T>
size_t Collection<T>::count()
{
	return this->_items.size();
}

template<class T>
void Collection<T>::add(T item)
{
	LOGGER_FUNCTION_BEGIN;

	this->_items.push_back(item);
}

template<class T>
T Collection<T>::items(size_t index)
{
	return this->_items.at(index);
}

template<class T>
void Collection<T>::remove(T item)
{
	LOGGER_FUNCTION_BEGIN;

	this->_items.erase(std::remove(this->_items.begin(), this->_items.end(), item), this->_items.end());
}

template<class T>
void Collection<T>::clear()
{
	LOGGER_FUNCTION_BEGIN;

	this->_items.clear();
}
