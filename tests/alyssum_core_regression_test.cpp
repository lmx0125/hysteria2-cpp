// Control-flow regressions for the real alyssum_core sources. All downstream
// stalls/dials are controlled mocks: no TUN, admin rights or public nodes.
#include "hytest.hpp"
#include "proxy_engine.hpp"
#include "node_prober.hpp"
#include "client_pool.hpp"
#include <algorithm>
#include <cstring>
#include <future>

namespace {
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
template<class F> bool Wait(F f, int ms=3000) {
    const auto end=Clock::now()+std::chrono::milliseconds(ms);
    while (!f() && Clock::now()<end) std::this_thread::sleep_for(1ms);
    return f();
}
uint16_t U16(const BYTE* p) { return uint16_t((p[0]<<8)|p[1]); }
uint32_t U32(const BYTE* p) { return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3]; }
void Put16(BYTE* p,uint16_t x) { p[0]=BYTE(x>>8);p[1]=BYTE(x); }
void Put32(BYTE* p,uint32_t x) {p[0]=BYTE(x>>24);p[1]=BYTE(x>>16);p[2]=BYTE(x>>8);p[3]=BYTE(x);}
uint16_t Sum(const BYTE* p,size_t n,uint32_t s=0) {
    for(size_t i=0;i+1<n;i+=2)s+=U16(p+i);
    if(n&1)s+=uint32_t(p[n-1])<<8;
    while(s>>16)s=(s&65535)+(s>>16);
    return uint16_t(~s);
}
constexpr uint32_t src=0x0a000002,dst=0x08080808;
std::vector<BYTE> Packet(uint32_t seq,uint32_t ack,BYTE flags,uint16_t win,
                         size_t bytes=0,bool scale=false,uint16_t port=40000) {
    const size_t h=scale?24:20;
    std::vector<BYTE> p(20+h+bytes,0x5a);
    std::fill(p.begin(),p.begin()+20+h,0);
    p[0]=0x45;Put16(&p[2],uint16_t(p.size()));p[8]=64;p[9]=6;
    Put32(&p[12],src);Put32(&p[16],dst);Put16(&p[10],Sum(p.data(),20));
    Put16(&p[20],port);Put16(&p[22],80);Put32(&p[24],seq);Put32(&p[28],ack);
    p[32]=BYTE((h/4)<<4);p[33]=flags;Put16(&p[34],win);
    if(scale){p[40]=3;p[41]=3;p[42]=0;p[43]=1;}
    uint32_t pseudo=(src>>16)+(src&65535)+(dst>>16)+(dst&65535)+6+uint32_t(h+bytes);
    Put16(&p[36],Sum(p.data()+20,h+bytes,pseudo));return p;
}
struct Stream:hy2::IByteReaderWriter {
    std::mutex mu;std::condition_variable cv;
    bool closed=false,blockWrite=true;
    size_t available=0;
    std::atomic<size_t> writeEntered{0},written{0},readCalls{0};
    std::atomic<bool> contentsOk{true};
    std::atomic<bool> writeClosed{false};
    size_t Read(uint8_t* p,size_t n) override {
        std::unique_lock lk(mu);++readCalls;
        cv.wait(lk,[&]{return closed||available>0;});
        if(closed)return 0;
        size_t got=std::min(n,available);available-=got;std::memset(p,0x63,got);return got;
    }
    void Write(const uint8_t* p,size_t n) override {
        ++writeEntered;std::unique_lock lk(mu);cv.wait(lk,[&]{return closed||!blockWrite;});
        if(closed)throw hy2::Error("closed");
        for(size_t i=0;i<n;++i)if(p[i]!=0x5a)contentsOk=false;
        written+=n;
    }
    void Close() override {{std::lock_guard lk(mu);closed=true;}cv.notify_all();}
    void CloseWrite() override { writeClosed=true; }
    void Feed(size_t n) {{std::lock_guard lk(mu);available+=n;}cv.notify_all();}
    void ReleaseWrite() {{std::lock_guard lk(mu);blockWrite=false;}cv.notify_all();}
};
struct Client:hy2::client::Client {
    std::shared_ptr<Stream> stream=std::make_shared<Stream>();
    std::atomic<bool> open{true};
    std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string&)override{return stream;}
    std::shared_ptr<hy2::client::HyUDPConn> UDP()override{return {};}
    bool IsOpen()const override{return open.load();}
    void Close()override{open=false;stream->Close();}
};
struct Fixture {
    std::shared_ptr<Client> client=std::make_shared<Client>();
    proxy::ProxyEngine engine;
    uint32_t initialSeq;uint16_t port;
    std::atomic<uint32_t> serverNext{0},ack{0};
    std::atomic<size_t> packets{0},bytes{0};std::atomic<uint16_t> window{0};
    std::atomic<bool> checksumsOk{true},fin{false},scaleOffered{false};
    std::atomic<int64_t> lastDataNs{0};
    std::function<bool(const BYTE*,DWORD)> sendBack;
    Fixture(uint16_t initialWindow=65535,bool scaled=true,uint32_t isn=1000,uint16_t p=40000)
        : initialSeq(isn),port(p) {
        sendBack=[this](const BYTE* d,DWORD n){
            const auto tcpLen=n-20;
            const uint32_t pseudo=(src>>16)+(src&65535)+(dst>>16)+(dst&65535)+6+tcpLen;
            if(Sum(d,20)!=0||Sum(d+20,tcpLen,pseudo)!=0)checksumsOk=false;
            if(d[33]&2){
                auto info=packet_parser::ParsePacket(d,n);scaleOffered=info.hasWindowScale;
                serverNext=U32(d+24)+1;
            }
            ack=U32(d+28);window=U16(d+34);
            if(d[33]&1)fin=true;
            size_t payload=n-20-((d[32]>>4)*4);
            if(payload){bytes+=payload;lastDataNs=std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();++packets;}
            return true;
        };
        engine.SetEventSink([](const auto&,const auto&){});
        engine.SetClient(client);Send(isn,0,2,initialWindow,0,scaled);
        if(!Wait([&]{return serverNext.load()!=0;}))throw hy2::Error("SYN-ACK timeout");
    }
    ~Fixture(){engine.Close();}
    void Send(uint32_t seq,uint32_t a,BYTE flags,uint16_t win,size_t n=0,bool scale=false){
        auto p=Packet(seq,a,flags,win,n,scale,port);
        auto info=packet_parser::ParsePacket(p.data(),DWORD(p.size()));
        HY_CHECK(engine.HandleTcpPacket(info,p.data(),DWORD(p.size()),sendBack));
    }
};
constexpr size_t capacity=size_t{65535}<<6;
void Fill(Fixture& f) {
    size_t sent=0;
    while(sent<capacity){
        const size_t n=std::min<size_t>(1400,capacity-sent);
        f.Send(f.initialSeq+1+uint32_t(sent),f.serverNext,0x18,65535,n);sent+=n;
        if(sent==1400)HY_CHECK(Wait([&]{return f.client->stream->writeEntered.load()==1;}));
    }
}
}

HY_TEST(AlyssumCore_UploadBoundsQueueAndDetachedBatch) {
    Fixture f;
    Fill(f);
    HY_CHECK_EQ(f.ack.load(),uint32_t(1001+capacity));
    HY_CHECK_EQ(f.window.load(),0);
    HY_CHECK_EQ(f.client->stream->written.load(),size_t{0});
    for(int i=0;i<100;++i)f.Send(1001+uint32_t(capacity),f.serverNext,0x18,65535,1400);
    HY_CHECK_EQ(f.ack.load(),uint32_t(1001+capacity));
    // Retransmitted/zero-window probe data must not be enqueued twice.
    f.Send(1000+uint32_t(capacity),f.serverNext,0x18,65535,1);
    HY_CHECK_EQ(f.ack.load(),uint32_t(1001+capacity));
    f.client->stream->ReleaseWrite();
    HY_CHECK(Wait([&]{return f.client->stream->written.load()==capacity && f.window.load()>0;}));
    f.Send(1001+uint32_t(capacity),f.serverNext,0x18,65535,1400);
    HY_CHECK(Wait([&]{return f.client->stream->written.load()==capacity+1400;}));
    HY_CHECK(f.client->stream->contentsOk.load());
    HY_CHECK(f.checksumsOk.load());
}

HY_TEST(AlyssumCore_OverflowFinIsNotAcknowledgedBeforePayload) {
    Fixture f;Fill(f);
    const uint32_t seq=1001+uint32_t(capacity);
    f.Send(seq,f.serverNext,0x19,65535,1400);
    HY_CHECK_EQ(f.ack.load(),seq);HY_CHECK(!f.fin.load());
    f.client->stream->ReleaseWrite();
    HY_CHECK(Wait([&]{return f.window.load()>0;}));
    f.Send(seq,f.serverNext,0x19,65535,1400);
    HY_CHECK(Wait([&]{return f.client->stream->written.load()==capacity+1400;}));
    HY_CHECK_EQ(f.ack.load(),seq+1401);
    HY_CHECK(Wait([&]{return f.client->stream->writeClosed.load();}));
    HY_CHECK(!f.fin.load()); // remote has not finished its response yet
}

HY_TEST(AlyssumCore_UnscaledWindowAndSequenceWrap) {
    Fixture f(65535,false,0xfffff000u);HY_CHECK(!f.scaleOffered.load());
    Fill(f);
    HY_CHECK_EQ(f.ack.load(),uint32_t(f.initialSeq+1+capacity));
    HY_CHECK_EQ(f.window.load(),0);
    f.client->stream->ReleaseWrite();
    HY_CHECK(Wait([&]{return f.window.load()==65535;}));
    HY_CHECK(f.checksumsOk.load());
}

HY_TEST(AlyssumCore_CloseInterruptsBlockedUpload) {
    Fixture f;f.Send(1001,f.serverNext,0x18,65535,1400);
    HY_CHECK(Wait([&]{return f.client->stream->writeEntered.load()==1;}));
    const auto t=Clock::now();f.engine.Close();
    HY_CHECK(Clock::now()-t<500ms);HY_CHECK_EQ(f.engine.WorkerCount(),size_t{0});
}

HY_TEST(AlyssumCore_ConsumingUploadCrossesCapacityRepeatedly) {
    Fixture f;f.client->stream->ReleaseWrite();
    const size_t total=capacity*3;
    size_t sent=0;
    const auto deadline=Clock::now()+10s;
    while(sent<total && Clock::now()<deadline){
        const size_t credit=size_t(f.window.load())<<6;
        if(credit==0){std::this_thread::sleep_for(1ms);continue;}
        const size_t n=std::min({size_t{1400},credit,total-sent});
        f.Send(1001+uint32_t(sent),f.serverNext,0x18,65535,n);
        // Only move the producer past bytes accepted by the engine.
        const auto accepted=uint32_t(f.ack.load()-1001);
        if(accepted>sent)sent=accepted;
    }
    HY_CHECK_EQ(sent,total);
    HY_CHECK(Wait([&]{return f.client->stream->written.load()==total;}));
    HY_CHECK(f.client->stream->contentsOk.load());HY_CHECK(f.checksumsOk.load());
}

HY_TEST(AlyssumCore_WindowOnlyUpdateWakesReader) {
    // With one byte of credit the reader parks after its first read. ACK all
    // data with window zero, then reopen without advancing ACK again.
    Fixture f(1);f.client->stream->Feed(2);
    HY_CHECK(Wait([&]{return f.packets.load()==1;}));
    f.Send(1001,f.serverNext+1,0x10,0);
    std::this_thread::sleep_for(40ms);
    HY_CHECK_EQ(f.client->stream->readCalls.load(),size_t{1});
    const auto start=Clock::now();
    f.Send(1001,f.serverNext+1,0x10,65535);
    HY_CHECK(Wait([&]{return f.packets.load()==2;}));
    const auto startNs=std::chrono::duration_cast<std::chrono::nanoseconds>(start.time_since_epoch()).count();
    const double ms=double(f.lastDataNs.load()-startNs)/1000000;
    std::printf("window-only resume: %.3f ms\n",ms);
    HY_CHECK(ms<100.0); // old code waits out the remaining ~150 ms poll
    HY_CHECK(f.checksumsOk.load());
}

HY_TEST(AlyssumCore_ConcurrentDownloadDiagnostics) {
    // Also run this test in a fresh process with ALYSSUM_DEBUG=1. A smoke
    // test for shared diagnostics; not a substitute for a race detector.
    std::vector<std::unique_ptr<Fixture>> flows;
    for(int i=0;i<8;++i)flows.push_back(std::make_unique<Fixture>(65535,true,1000,uint16_t(41000+i)));
    for(auto& f:flows)f->client->stream->Feed(32768);
    for(auto& f:flows){HY_CHECK(Wait([&]{return f->bytes.load()==32768;}));HY_CHECK(f->checksumsOk.load());}
}

namespace {
std::shared_ptr<Client> ProbeClient(){
    auto c=std::make_shared<Client>();c->stream->ReleaseWrite();c->stream->Feed(1);return c;
}
nodes::Node TestNode(){nodes::Node n;n.server="mock:443";return n;}
HyClientPool::Config PoolConfig(){HyClientPool::Config c;c.size=1;c.bandwidthBackoff=false;return c;}
struct DialGate {
    std::mutex mu;std::condition_variable cv;bool released=false,entered=false,fail=false;
    std::atomic<int> calls{0};
    std::shared_ptr<hy2::client::Client> Dial(const hy2::client::Config&,hy2::client::HandshakeInfo*){
        if(++calls==1)return std::make_shared<Client>();
        std::unique_lock lk(mu);entered=true;cv.notify_all();cv.wait(lk,[&]{return released;});
        if(fail)throw hy2::Error("controlled dial failure");
        return std::make_shared<Client>();
    }
    bool WaitEntered(){std::unique_lock lk(mu);return cv.wait_for(lk,2s,[&]{return entered;});}
    void Release(){{std::lock_guard lk(mu);released=true;}cv.notify_all();}
};
}

HY_TEST(AlyssumCore_ProbeHealthyIntervalAndPromptStop) {
    std::atomic<int> calls{0};
    nodes::NodeProber p([&](const auto&,auto*){++calls;return ProbeClient();});
    p.Start({TestNode()},{});
    HY_CHECK(Wait([&]{return p.Status(0).state==nodes::NodeState::Up;}));
    std::this_thread::sleep_for(150ms);HY_CHECK_EQ(calls.load(),1);
    const auto t=Clock::now();p.Stop();HY_CHECK(Clock::now()-t<250ms);
    p.Start({TestNode()},{});
    HY_CHECK(Wait([&]{return calls.load()==2;}));p.Stop();
}

HY_TEST(AlyssumCore_ProbeFailureDebounceAndRetrySchedule) {
    std::atomic<int> calls{0};
    nodes::NodeProber p([&](const auto&,auto*)->std::shared_ptr<hy2::client::Client>{++calls;throw hy2::Error("offline");},30s,150ms);
    p.Start({TestNode()},{});
    HY_CHECK(Wait([&]{return calls.load()==1;}));
    std::this_thread::sleep_for(40ms);HY_CHECK_EQ(calls.load(),1);
    HY_CHECK(p.Status(0).state==nodes::NodeState::Unknown);
    HY_CHECK(Wait([&]{return p.Status(0).state==nodes::NodeState::Down;}));p.Stop();
    HY_CHECK_EQ(calls.load(),2);
}

HY_TEST(AlyssumCore_ProbeEveryNodeBeforeRepeatAndEmptyStop) {
    std::atomic<int> calls{0};
    nodes::NodeProber p([&](const auto&,auto*){++calls;return ProbeClient();});
    p.Start({TestNode(),TestNode(),TestNode()},{});
    HY_CHECK(Wait([&]{return p.Status(2).state==nodes::NodeState::Up;}));
    HY_CHECK_EQ(calls.load(),3);p.Stop();
    p.Start({},{});const auto t=Clock::now();p.Stop();HY_CHECK(Clock::now()-t<250ms);
}

HY_TEST(AlyssumCore_ProbeSuccessfulRetryClearsDataFailure) {
    struct RetryClient : Client {
        std::atomic<int> attempts{0};
        std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string&) override {
            if (++attempts==1) throw hy2::Error("transient stream failure");
            return stream;
        }
    };
    auto client=std::make_shared<RetryClient>();
    client->stream->ReleaseWrite();client->stream->Feed(1);
    nodes::NodeProber p([&](const auto&,auto*){return client;});
    p.Start({TestNode()},{});
    HY_CHECK(Wait([&]{return p.Status(0).state==nodes::NodeState::Up;}));
    const auto st=p.Status(0);p.Stop();
    HY_CHECK_EQ(client->attempts.load(),2);HY_CHECK(!st.dataFailed);HY_CHECK(st.error.empty());
}

HY_TEST(AlyssumCore_ProbeNullClientCannotReportHealthy) {
    nodes::NodeProber p([](const auto&,auto*)->std::shared_ptr<hy2::client::Client>{return {};},30s,30ms);
    p.Start({TestNode()},{});
    HY_CHECK(Wait([&]{return p.Status(0).state==nodes::NodeState::Down;}));
    HY_CHECK(!p.Status(0).error.empty());p.Stop();
}

HY_TEST(AlyssumCore_PoolPublishesToAllWaiters) {
    DialGate gate;
    HyClientPool p([&](const auto& c,auto* h){return gate.Dial(c,h);});
    HY_CHECK(p.Start(PoolConfig()));auto first=p.Acquire();p.MarkDead(first);
    const bool entered=gate.WaitEntered();
    std::vector<std::future<std::shared_ptr<hy2::client::Client>>> waiters;
    for(int i=0;i<8;++i)waiters.push_back(std::async(std::launch::async,[&]{return p.Acquire();}));
    std::this_thread::sleep_for(30ms);const auto t=Clock::now();gate.Release();
    bool ok=true;for(auto& w:waiters){auto c=w.get();ok=ok&&c&&c!=first;}
    const auto elapsed=Clock::now()-t;p.Stop();
    HY_CHECK(entered);HY_CHECK(ok);HY_CHECK(elapsed<500ms);
    std::printf("pool publication to 8 waiters: %.3f ms\n",std::chrono::duration<double,std::milli>(elapsed).count());
}

HY_TEST(AlyssumCore_PoolQuickPathNeverWaitsForDial) {
    DialGate gate;HyClientPool p([&](const auto& c,auto* h){return gate.Dial(c,h);});
    HY_CHECK(p.Start(PoolConfig()));p.MarkDead(p.Acquire());
    const bool entered=gate.WaitEntered();const auto t=Clock::now();
    const auto a=p.Acquire(false),b=p.Acquire(true,false);const auto elapsed=Clock::now()-t;
    gate.Release();p.Stop();HY_CHECK(entered);HY_CHECK(!a&&!b);HY_CHECK(elapsed<100ms);
}

HY_TEST(AlyssumCore_PoolFailedReconnectReleasesWaiter) {
    DialGate gate;gate.fail=true;HyClientPool p([&](const auto& c,auto* h){return gate.Dial(c,h);});
    HY_CHECK(p.Start(PoolConfig()));auto old=p.Acquire();old->Close();p.MarkDead(old);
    const bool entered=gate.WaitEntered();auto w=std::async(std::launch::async,[&]{return p.Acquire();});
    std::this_thread::sleep_for(30ms);gate.Release();
    const bool ready=w.wait_for(500ms)==std::future_status::ready;auto result=w.get();p.Stop();
    HY_CHECK(entered);HY_CHECK(ready);HY_CHECK(!result);
}

HY_TEST(AlyssumCore_PoolStopWakesWaiterBeforeDialFinishes) {
    DialGate gate;HyClientPool p([&](const auto& c,auto* h){return gate.Dial(c,h);});
    HY_CHECK(p.Start(PoolConfig()));p.MarkDead(p.Acquire());const bool entered=gate.WaitEntered();
    auto w=std::async(std::launch::async,[&]{return p.Acquire();});
    std::this_thread::sleep_for(30ms);auto stop=std::async(std::launch::async,[&]{p.Stop();});
    const bool ready=w.wait_for(500ms)==std::future_status::ready;
    gate.Release();stop.get();auto result=w.get();HY_CHECK(entered);HY_CHECK(ready);HY_CHECK(!result);
}


namespace {
struct LimitedClient : Client {
    std::atomic<int> calls{0};
    std::atomic<bool> limited{false};
    std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string& addr) override {
        ++calls;
        if(limited.load()) throw hy2::StreamLimitReachedError();
        return Client::TCP(addr);
    }
};
}
HY_TEST(AlyssumCore_StreamLimitPreservesExistingConnection) {
    auto client=std::make_shared<LimitedClient>();
    client->stream->ReleaseWrite();
    std::atomic<int> dials{0};
    HyClientPool pool([&](const auto&,auto*){++dials;return client;});
    HY_CHECK(pool.Start(PoolConfig()));
    auto existing=pool.TCP("existing:80");
    client->limited=true;
    bool limited=false;
    try{pool.TCP("new:80");}catch(const hy2::StreamLimitReachedError&){limited=true;}catch(...){}
    std::this_thread::sleep_for(100ms); // detect an incorrectly queued reconnect
    const bool open=client->IsOpen();
    const int dialCount=dials.load();
    client->limited=false;
    auto recovered=pool.TCP("recovered:80");
    const uint8_t data=0x5a;
    existing->Write(&data,1);
    pool.Stop();
    HY_CHECK(limited && open && recovered);
    HY_CHECK_EQ(dialCount,1);
    HY_CHECK_EQ(client->stream->written.load(),size_t{1});
}
HY_TEST(AlyssumCore_StreamLimitRetriesOtherSlot) {
    auto first=std::make_shared<LimitedClient>();
    auto second=std::make_shared<LimitedClient>();
    std::atomic<int> dials{0};
    HyClientPool pool([&](const auto&,auto*){return ++dials==1?first:second;});
    auto cfg=PoolConfig();cfg.size=2;
    HY_CHECK(pool.Start(cfg));pool.Warmup();
    const bool ready=Wait([&]{return pool.LiveCount()==2;});
    first->limited=true;
    bool ok=ready;
    for(int i=0;i<4 && ok;++i)try{ok=pool.TCP("test:80")==second->stream;}catch(...){ok=false;}
    const bool open=first->IsOpen() && second->IsOpen();
    const int dialCount=dials.load();
    pool.Stop();
    HY_CHECK(ok && open);
    HY_CHECK_EQ(dialCount,2);
    HY_CHECK(first->calls.load()>0);
}
