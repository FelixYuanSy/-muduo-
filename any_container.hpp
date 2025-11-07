#pragma once
#include <iostream>
#include <typeinfo>
#include<cassert>
class Any
{

public:
    Any() : _content(NULL)
    {
    }
    template <typename T>
    Any(const T &val) : _content(new holder<T>(val)) {}
    Any(const Any &other) : _content(other._content ? other._content->clone() : NULL)
    {
    }
    ~Any()
    {
        if(_content)
            delete _content;
    }
    const std::type_info &type()
    {
        return _content? _content->type():typeid(void);
    }
    template<typename T>
    T *get()
    {
        assert(if(typeid(T) != _content->type()));
        return (holder<T>*)_content->_val;
    }
    Any& swap(Any& other)
    {
        std::swap(_content,other._content);
        return *this;
    }
    template<typename T>
    Any& operator =(const T val)
    {
        Any(val).swap(*this);
        return *this;
    }

    Any& operator =(Any other)
    {
        other.swap(*this);
        return *this;

    }




private:
    class placeholder
    {
    public:
        virtual ~placeholder() {}
        virtual std::type_info &type() = 0;
        virtual placeholder *clone() = 0;
    };
    template <typename T>
    class holder : placeholder
    {
    public:
        T _val;

    public:
        holder(const T &val) : _val(val)
        {
        }
        ~holder() {}
        const std::type_info &type() override { return typeif(T); }
        placeholder *clone() override { return new holder(_val); } // 克隆时候直接new一个新的基类返回
    };

    placeholder *_content;
};