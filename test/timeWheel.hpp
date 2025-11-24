#pragma once
#include <iostream>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <memory>
#include <vector>

using TaskFunc = std::function<void()>;    // 用来传入定时任务
using ReleaseFunc = std::function<void()>; // 用来删除定时器对象信息
class TimerTask
{
private:
    uint64_t _id;         // 任务id
    uint32_t _timeout;    // 定时任务超时时间
    TaskFunc _task_cb;    // 定时器要执行的任务
    ReleaseFunc _release; // 用来删除timerwheel里定时器对象

public:
    TimerTask(uint64_t id, uint32_t timeout, const TaskFunc &task_cb) : _id(id), _timeout(timeout), _task_cb(task_cb)
    {
    }
    ~TimerTask()
    {
        _task_cb();
        _release();
    }
    void SetRelease(const ReleaseFunc &cb)
    {
        _release = cb;
    }
    uint32_t GetDelayTime()
    {
        return _timeout;
    }
};

class TimerWheel
{
private:
    using PtrTask = std::shared_ptr<TimerTask>;
    using WeakTask = std::weak_ptr<TimerTask>;
    int _tick;                                      // 轮子当前时间指针
    int _capacity;                                  // 最大延迟时间
    std::vector<std::vector<PtrTask>> _wheel;       // 二维数组,用来存时间轮中的任务
    std::unordered_map<uint64_t, WeakTask> _timers; // 用弱指针来移除timer,弱指针不占用计数
private:
    void RemoveTimer(uint64_t id)
    {
        auto it = _timers.find(id);
        if(it != _timers.end())
        {
            _timers.erase(it);
        }
    }
public:
    TimerWheel():_tick(0),_capacity(60),_wheel(_capacity)
    {

    }

    void TimerAdd(uint64_t id, uint32_t timeout, const TaskFunc &cb)
    {
        PtrTask pt(new TimerTask(id,timeout,cb)); 
        pt->SetRelease(std::bind(RemoveTimer,this,id));
        int pos = (_tick + timeout)%_capacity;
        _wheel[pos].push_back(pt);
        _timers[id] = WeakTask(pt);
        
    }

    void TimerRefresh(uint64_t id)
    {
        auto it = _timers.find(id);
        if(it == _timers.end())
        {
            return;     //没找到任务,代表无法刷新
        }
        PtrTask pt = it->second.lock();
        int delaytime = pt->GetDelayTime();
        int pos = (_tick + delaytime) % _capacity;
        _wheel[pos].push_back(pt);
    }

    void Runtick()
    {
        _tick = (_tick + 1) % _capacity;    //每次走一个时间点
        _wheel[_tick].clear();              //调用clear清除当前时间点上的任务,任务的析构函数会让任务自己运行
    }
};