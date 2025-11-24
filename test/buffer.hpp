#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <assert.h>
#include <cstring>
/*
        buffer使用vector来储存
        读和写需要偏移量,因为采用空间地址来管理数据位置
        需要位置功能:
        1.获取可读空间大小/
        2.获取读取位置: 写入偏移-读取偏移/
        3.获取写入位置/
        4.获取缓冲末尾空闲空间大小/
        5.获取缓冲区起始空闲空间大小/
        6.查看是否可写: 写入长度 >= 起始 + 末尾缓冲空间大小/
        7.移动读位置/
        8.移动写位置/

        写入功能:
        1. 写入数据(要输入数据,长度)/写入并移动/
        2. 读取数据((输出参数),读取长度)/读取并移动/
        3. 读取为string/+移动/
        4. 查找\n标识符
        5.获取行内容
        6.清空缓冲区
    */
#define BUFFER_DEFAULT_SIZE 1024
class Buffer
{
private:
    std::vector<char> _buffer;
    uint64_t _reader_idx;
    uint64_t _writer_idx;

public:
    Buffer() : _reader_idx(0), _writer_idx(0), _buffer(BUFFER_DEFAULT_SIZE) {}
    Buffer(Buffer &other)
    {
        Write(other.ReadPosition(), other.ReadableSize());
        MoveReaderOffset(other.ReadableSize());
    }
    char *Begin()
    {
        return &*_buffer.begin(); // 返回空间地址
    }
    char *ReadPosition()
    {
        return Begin() + _reader_idx;
    }
    char *WritePosition()
    {
        return Begin() + _writer_idx;
    }
    uint64_t TailIdleSize()
    {
        return _buffer.size() - _writer_idx;
    }
    uint64_t FrontIdleSize()
    {
        return _reader_idx;
    }
    uint64_t ReadableSize()
    {
        return _writer_idx - _reader_idx;
    }
    void EnsureWriteSpace(uint64_t len)
    {
        if (len <= TailIdleSize())
        {
            return;
        }
        if (len <= TailIdleSize() + FrontIdleSize())
        {
            uint64_t rsz = ReadableSize();
            std::copy(ReadPosition(), ReadPosition() + rsz, Begin());
            _reader_idx = 0;
            _writer_idx = rsz;
        }
        else
        {
            _buffer.resize(_writer_idx + len);
        }
    }
    void MoveReaderOffset(uint64_t len)
    {
        assert(len <= ReadableSize());
        _reader_idx += len;
    }
    void MoveWriterOffset(uint64_t len)
    {
        assert(len <= TailIdleSize());
        _writer_idx += len;
    }
    void Write(const void *data, uint64_t len)
    {
        if (len = 0)
            return;
        EnsureWriteSpace(len);
        char *d = (char *)data;
        std::copy(d, d + len, WritePosition());
    }
    void WriteAndMove(const void *data, uint64_t len)
    {
        Write(data, len);
        MoveWriterOffset(len);
    }
    void WriteString(const std::string &data)
    {
        Write(data.c_str(), data.size());
    }
    void WriteStringAndMove(const std::string &data)
    {
        WriteString(data);
        MoveWriterOffset(data.size());
    }

    void Read(void *buf, uint64_t len)
    {
        assert(len <= ReadableSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *)buf);
    }
    void ReadAndMove(void *buf, uint64_t len)
    {
        Read(buf, len);
        MoveReaderOffset(len);
    }
    std::string ReadAsString(uint64_t len)
    {
        assert(len <= ReadableSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str;
    }
    std::string ReadAsStringAndMove(uint64_t len)
    {
        assert(len <= ReadableSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    char *FindCRLF()
    {
        char *res = (char *)memchr(ReadPosition(), '\n', ReadableSize());
        return res;
    }
    std::string GetLine()
    {
        char *pos = FindCRLF();
        if (pos == NULL)
            return "";
        return ReadAsString(pos - ReadPosition() + 1); //+1读取\n
    }
    std::string GetLineAndPop()
    {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    void Clear()
    {
        _reader_idx = 0;
        _writer_idx = 0;
    }
};